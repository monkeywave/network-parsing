# fb_logging_client_events_dump.py
# Usage:
#   mitmdump -nr capture.mitm -s deflate_fb_traffic.py \
#       --set fb_dump_dir=./decoded_cmsg --set fb_print_mode=1
#   (also works live with mitmproxy)
#
# Print modes:
#   1 (default): concise logs (like before) + hexdump previews for binary parts
#   2: multipart view (headers + values); binary parts show a hexdump preview
#   3: plain decoded view; binary parts are decompressed (if gzip) and printed; JSON pretty-printed
#
# Features:
# - Watches POSTs to https://graph.facebook.com/logging_client_events
# - Handles x-www-form-urlencoded, JSON, and multipart/form-data
# - Extracts "cmsg" values, handles gzip + base64, writes .bin/.txt and .raw_gzip
# - Multipart binary parts -> per-part .part.bin + full .hex; combined .raw_binary_body.bin
# - Robust multipart parsing:
#     * Primary: email.parser using RAW Content-Type (case preserved)
#     * Fallback: manual boundary splitter (case sensitive, CRLF/LF tolerant)
# - Rich diagnostics; auto-creates output directory
# - NEW: Whenever decoded content is valid JSON, also save a pretty file: *.json

from mitmproxy import http, ctx
from pathlib import Path
import urllib.parse
import gzip
import zlib
import base64
import json
import time
import re
from typing import List, Dict, Any, Optional, Tuple

from email.parser import BytesParser
from email.policy import default as email_default

GRAPH_HOST = "graph.facebook.com"
LCE_PATH_PREFIX = "/logging_client_events"
PHOTO_PATH_RE = re.compile(r"^/\d+/photos(?:\?.*)?$")
TARGETS = [
    ("graph.facebook.com", "/logging_client_events"),
    ("www.instagram.com", "/ajax/bz"),          # NEW
    ("instagram.com", "/ajax/bz"),              # sometimes no www
]

def _guess_image_ext(ct: str, sniff: bytes, filename: str = "") -> str:
    # 1) filename wins
    if filename and "." in filename and not filename.lower().endswith(".tmp"):
        ext = filename.rsplit(".", 1)[1].lower()
        return ext

    # 2) content-type
    if ct:
        if "jpeg" in ct: return "jpg"
        if "png" in ct:  return "png"
        if "gif" in ct:  return "gif"
        if "webp" in ct: return "webp"
        if "heic" in ct or "heif" in ct: return "heic"
        if "avif" in ct: return "avif"
        if "bmp" in ct:  return "bmp"
        if "image/" in ct: return ct.split("/",1)[1].split(";")[0].strip().lower()

    # 3) magic bytes
    if sniff.startswith(b"\xFF\xD8\xFF"): return "jpg"
    if sniff.startswith(b"\x89PNG\r\n\x1a\n"): return "png"
    if sniff.startswith(b"GIF87a") or sniff.startswith(b"GIF89a"): return "gif"
    if sniff[:4] == b"RIFF" and b"WEBP" in sniff[:16]: return "webp"
    if b"ftypheic" in sniff[:32] or b"ftypheif" in sniff[:32]: return "heic"
    if b"ftypavif" in sniff[:32]: return "avif"
    if sniff.startswith(b"BM"): return "bmp"
    return "bin"


def _maybe_decode_data_url(src: bytes) -> Optional[bytes]:
    """
    Support data URLs like: b'data:image/jpeg;base64,/9j/4AAQ...'
    """
    try:
        s = src.decode("utf-8", "replace").strip()
        if s.startswith("data:"):
            head, _, b64 = s.partition(";base64,")
            if b64:
                return base64.b64decode(b64)
    except Exception:
        pass
    return None



def _now_tag() -> str:
    return time.strftime("%Y%m%d-%H%M%S")

def _ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)

def _looks_gzip(b: bytes) -> bool:
    return len(b) >= 2 and b[0] == 0x1F and b[1] == 0x8B

def _parse_form_bytes(body: bytes) -> Dict[str, List[bytes]]:
    qsl = urllib.parse.parse_qsl(body.decode("latin-1", "replace"), keep_blank_values=True)
    out: Dict[str, List[bytes]] = {}
    for k, v in qsl:
        kb = urllib.parse.unquote_to_bytes(k)
        vb = urllib.parse.unquote_to_bytes(v)
        out.setdefault(kb.decode("latin-1", "ignore"), []).append(vb)
    return out

def _try_base64(s: str) -> Optional[bytes]:
    t = s.strip()
    if len(t) < 8:
        return None
    rem = len(t) % 4
    if rem:
        t = t + ("=" * (4 - rem))
    try:
        return base64.b64decode(t, validate=False)
    except Exception:
        return None

def _bytes_from_json_string(s: str) -> bytes:
    b = _try_base64(s)
    if b is not None:
        return b
    return s.encode("latin-1", "replace")

def _collect_cmsg_bytes_from_json(obj: Any) -> List[bytes]:
    results: List[bytes] = []
    def add_if_cmsg(val: Any):
        if isinstance(val, str):
            results.append(_bytes_from_json_string(val))
    if isinstance(obj, dict):
        if "cmsg" in obj: add_if_cmsg(obj["cmsg"])
        if "cmsgs" in obj and isinstance(obj["cmsgs"], list):
            for it in obj["cmsgs"]:
                if isinstance(it, str): results.append(_bytes_from_json_string(it))
        for _, v in obj.items():
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, dict) and "cmsg" in item:
                        add_if_cmsg(item["cmsg"])
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict) and "cmsg" in item:
                add_if_cmsg(item["cmsg"])
    return results

def _safe_text_preview(b: bytes, limit: int) -> str:
    t = b.decode("utf-8", "replace")
    return t if len(t) <= limit else t[:limit] + f"... [truncated {len(t) - limit} chars]"

def _hexdump(b: bytes, max_len: int = 256) -> str:
    data = b[:max_len]
    lines: List[str] = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hexpart = " ".join(f"{x:02x}" for x in chunk[:8])
        if len(chunk) > 8:
            hexpart += "  " + " ".join(f"{x:02x}" for x in chunk[8:])
        asciipart = "".join(chr(x) if 32 <= x <= 126 else "." for x in chunk)
        lines.append(f"{i:08x}  {hexpart:<48}  |{asciipart}|")
    if len(b) > max_len:
        lines.append(f"... [truncated {len(b) - max_len} bytes]")
    return "\n".join(lines)

def _write_full_hexdump(path: Path, b: bytes):
    with open(path, "w", encoding="utf-8") as f:
        for i in range(0, len(b), 16):
            chunk = b[i:i+16]
            hexpart = " ".join(f"{x:02x}" for x in chunk[:8])
            if len(chunk) > 8:
                hexpart += "  " + " ".join(f"{x:02x}" for x in chunk[8:])
            asciipart = "".join(chr(x) if 32 <= x <= 126 else "." for x in chunk)
            f.write(f"{i:08x}  {hexpart:<48}  |{asciipart}|\n")

def _save_text(path: Path, data: bytes):
    text_out = data.decode("utf-8", "replace")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text_out)

def _looks_zlib(b: bytes) -> bool:
    # Common zlib CMF/FLG combos start with 0x78 0x01/0x5E/0x9C/0xDA
    return len(b) >= 2 and b[0] == 0x78 and b[1] in (0x01, 0x5E, 0x9C, 0xDA)

def _decompress_any(payload: bytes) -> Tuple[bytes, str]:
    """
    Try gzip -> zlib -> raw deflate. Returns (decompressed_bytes, algo_name)
    algo_name is one of: 'gzip', 'zlib', 'deflate', or 'raw' (unchanged).
    """
    if _looks_gzip(payload):
        try:
            return gzip.decompress(payload), "gzip"
        except Exception:
            pass
    if _looks_zlib(payload):
        try:
            return zlib.decompress(payload), "zlib"  # wbits=+15 (zlib header)
        except Exception:
            pass
    # try raw deflate stream
    try:
        ctx.log.warn("running raw decompress...")
        return zlib.decompress(payload, wbits=-15), "deflate"  # raw
    except Exception:
        return payload, "raw"


def _decompress(payload: bytes) -> bytes:
    dec, _algo = _decompress_any(payload)
    return dec

# --- NEW: JSON pretty-print save helper --------------------------------------

def _try_save_json(outdir: Path, suffix: str, data: bytes) -> bool:
    """
    Try to parse 'data' as JSON. If successful, write pretty JSON to <suffix>.json
    and return True. If not JSON, return False.
    """
    try:
        # Allow BOM/whitespace
        txt = data.lstrip(b"\xef\xbb\xbf \t\r\n").decode("utf-8")
        obj = json.loads(txt)
        pretty = json.dumps(obj, indent=2, ensure_ascii=False)
        json_path = outdir / f"{suffix}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            f.write(pretty + "\n")
        ctx.log.info(f"[fb-post_0] Wrote JSON  -> {json_path}")
        return True
    except Exception:
        return False

def _decompress_and_save(outdir: Path, suffix: str, payload: bytes) -> None:
    """
    Decompress if gzip, then save:
      - <suffix>.raw_gzip (if original was gzipped)
      - <suffix>.bin (decoded bytes)
      - <suffix>.txt (UTF-8 best-effort)
      - <suffix>.json (NEW, if decoded bytes are valid JSON)
    """
    if _looks_gzip(payload):
        try:
            decompressed = gzip.decompress(payload)
            raw_path = outdir / f"{suffix}.raw_gzip"
            with open(raw_path, "wb") as f:
                f.write(payload)
            ctx.log.info(f"[fb-post_0] Wrote original gzip -> {raw_path}")
        except Exception as e:
            ctx.log.error(f"[fb-post_0] gzip decompress failed: {e}; using raw as-is")
            decompressed = payload
    elif _looks_zlib(payload):
        try:
            decompressed, algo = _decompress_any(payload)
            raw_path = outdir / f"{suffix}.raw_zlib"
            with open(raw_path, "wb") as f:
                f.write(payload)
            ctx.log.info(f"[fb-post_0] Wrote original zlib -> {raw_path}")
        except Exception as e:
            ctx.log.error(f"[fb-post_0] zlib decompress failed: {e}; using raw as-is")
            decompressed = payload
    else:
        decompressed = payload
        ctx.log.info("[fb-post_0] Not gzipped and not zlibed; saving raw as decompressed")

    bin_path = outdir / f"{suffix}.bin"
    with open(bin_path, "wb") as f:
        f.write(decompressed)
    ctx.log.info(f"[fb-post_0] Wrote bytes -> {bin_path}")

    txt_path = outdir / f"{suffix}.txt"
    _save_text(txt_path, decompressed)
    ctx.log.info(f"[fb-post_0] Wrote text  -> {txt_path}")

    # NEW: save pretty JSON if possible
    _ = _try_save_json(outdir, suffix, decompressed)

# ---------- Manual multipart fallback (case-sensitive boundary) ----------

def _parse_boundary_from_header(ctype_raw: str) -> Optional[str]:
    m = re.search(r'boundary=(?P<b>[^;]+)', ctype_raw)
    if not m:
        return None
    b = m.group('b').strip().strip('"')
    return b

def _manual_split_parts(body: bytes, boundary: str) -> List[bytes]:
    bndry = boundary.encode("latin-1", "ignore")
    delim = b"--" + bndry
    end = b"--" + bndry + b"--"
    if delim not in body:
        return []
    first = body.find(delim)
    core = body[first:]
    if end in core:
        core = core.split(end, 1)[0]
    segments = core.split(delim)
    parts: List[bytes] = []
    for seg in segments[1:]:
        if seg.startswith(b"\r\n"):
            seg = seg[2:]
        elif seg.startswith(b"\n"):
            seg = seg[1:]
        if not seg.strip():
            continue
        parts.append(seg)
    return parts

def _split_headers_content(block: bytes) -> Tuple[Dict[str, str], bytes]:
    m = re.search(rb'\r\n\r\n|\n\n', block)
    if not m:
        return {}, block
    header_blob = block[:m.start()]
    content = block[m.end():]
    headers: Dict[str, str] = {}
    for line in header_blob.splitlines():
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.decode("latin-1", "ignore").strip().lower()] = v.decode("latin-1", "ignore").strip()
    return headers, content

def _heuristic_extract_first_binary_section(body: bytes, boundary: str) -> Optional[bytes]:
    bndry = boundary.encode("latin-1", "ignore")
    marker = b"content-transfer-encoding:"
    pos = body.lower().find(marker + b" binary")
    if pos < 0:
        pos = body.lower().find(marker)
        if pos < 0:
            return None
        line_end = body.find(b"\n", pos)
        if line_end < 0 or b"binary" not in body[pos:line_end].lower():
            return None
    start = body.find(b"\r\n\r\n", pos)
    sep_len = 4
    if start < 0:
        start = body.find(b"\n\n", pos)
        sep_len = 2
        if start < 0:
            return None
    start += sep_len
    next_b = body.find(b"\r\n--" + bndry, start)
    if next_b < 0:
        next_b = body.find(b"\n--" + bndry, start)
    end = next_b if next_b >= 0 else len(body)
    return body[start:end]

# ---------- Multipart via email parser (using RAW Content-Type) ----------

def _cd_param(cd_value: str, key: str) -> Optional[str]:
    m = re.search(rf'{key}\s*=\s*"([^"]*)"', cd_value)
    return m.group(1) if m else None

def _iter_multipart_parts(body: bytes, ctype_raw: str):
    boundary = _parse_boundary_from_header(ctype_raw)
    header_blob = f"Content-Type: {ctype_raw}\r\nMIME-Version: 1.0\r\n\r\n".encode("latin-1", "ignore")
    msg = BytesParser(policy=email_default).parsebytes(header_blob + body)

    if msg.is_multipart():
        for idx, part in enumerate(msg.iter_parts(), 1):
            payload = part.get_payload(decode=True)
            if payload is None:
                content_str = part.get_content()
                payload = content_str.encode("utf-8", "replace")
            yield {
                "idx": idx,
                "name": part.get_param("name", header="content-disposition") or f"part{idx}",
                "filename": part.get_param("filename", header="content-disposition") or "",
                "ct": (part.get_content_type() or "").lower(),
                "cte": (part.get("Content-Transfer-Encoding") or "").lower(),
                "payload": payload,
                "headers": {k.lower(): v for k, v in part.items()},
            }
        return

    # Manual fallback
    if not boundary:
        return
    raw_parts = _manual_split_parts(body, boundary)
    for idx, raw in enumerate(raw_parts, 1):
        headers, payload = _split_headers_content(raw)
        yield {
            "idx": idx,
            "name": _cd_param(headers.get("content-disposition",""), "name") or f"part{idx}",
            "filename": _cd_param(headers.get("content-disposition",""), "filename") or "",
            "ct": headers.get("content-type","").lower(),
            "cte": headers.get("content-transfer-encoding","").lower(),
            "payload": payload,
            "headers": headers,
        }

# ---------- Pretty printers for modes 2 & 3 ----------

def _print_multipart_view(boundary: str, parts: List[Dict[str, Any]], mode: int):
    """
    mode 2: textual parts as plain, binary parts as hexdump preview
    mode 3: textual parts as plain, binary parts decompressed+printed (JSON pretty if possible; else hexdump)
    """
    for p in parts:
        name = p["name"]; filename = p["filename"]; ct = p["ct"]; cte = p["cte"]; payload = p["payload"]; headers = p["headers"]
        ctx.log.info(f"--{boundary}")
        cd = f'form-data; name="{name}"' + (f'; filename="{filename}"' if filename else "")
        ctx.log.info(f"Content-Disposition: {cd}")
        if ct:
            orig_ct = headers.get("content-type", ct)
            ctx.log.info(f"Content-Type: {orig_ct}")
        if cte:
            ctx.log.info(f"Content-Transfer-Encoding: {cte}")
        ctx.log.info("")

        if cte == "binary" or ct == "application/octet-stream":
            if mode == 2:
                ctx.log.info("hexdump preview:")
                ctx.log.info(_hexdump(payload, 256))
            else:
                blob = _decompress(payload)
                try:
                    txt = blob.decode("utf-8")
                    txt_stripped = txt.strip()
                    if (txt_stripped.startswith("{") and txt_stripped.endswith("}")) or \
                       (txt_stripped.startswith("[") and txt_stripped.endswith("]")):
                        pretty = json.dumps(json.loads(txt_stripped), ensure_ascii=False, indent=2)
                        ctx.log.info(pretty)
                    else:
                        if sum(ch < 9 or (13 < ch < 32) for ch in blob[:128]) > 5:
                            ctx.log.info("hexdump preview:")
                            ctx.log.info(_hexdump(blob, 256))
                        else:
                            ctx.log.info(txt)
                except Exception:
                    ctx.log.info("hexdump preview:")
                    ctx.log.info(_hexdump(blob, 256))
        else:
            try:
                ctx.log.info(p["payload"].decode("utf-8", "replace").rstrip("\r\n"))
            except Exception:
                ctx.log.info(_safe_text_preview(p["payload"], 4096).rstrip("\r\n"))

    ctx.log.info(f"--{boundary}--")

# ---------------- Addon ----------------

class FbCmsgDumper:
    def load(self, loader):
        loader.add_option("fb_dump_dir", str, "./deflate_fb_traffic.py",
                          "Directory for dumped Facebook logging_client_events payloads.")
        loader.add_option("fb_preview_chars", int, 4096,
                          "Max characters to print as body preview in event log.")
        loader.add_option("fb_print_mode", int, 1,
                          "Print mode: 1=concise (default), 2=multipart view + hexdump for binary, 3=plain decoded + JSON pretty.")
        loader.add_option(
            "fb_form_binary_keys", str, r"^(cmsg|post_\d+)$",
            "Regex of form field names that may contain binary/compressed payloads."
        )
        loader.add_option("fb_photo_dir", str, "./fb_photo_dumps",
                  "Directory for dumped photo uploads (/NUMERIC_ID/photos).")


    def _handle_rupload_photo(self, flow: http.HTTPFlow) -> None:
        """
        Handle POST https://rupload.facebook.com/fb_photo/
        The whole body is the raw image bytes (no multipart, no form fields).
        """
        outdir = Path(ctx.options.fb_photo_dir)
        _ensure_dir(outdir)

        rid = f"{_now_tag()}_{flow.id}"
        ct = (flow.request.headers.get("content-type") or "").lower()
        body = flow.request.get_content() or b""

        ctx.log.info(f"[fb-cmsg] RUpload photo POST: {flow.request.pretty_url} (flow.id={flow.id})")
        ctx.log.info(f"[fb-cmsg] Content-Type='{ct}', Content-Length={flow.request.headers.get('content-length','?')}")

        if not body:
            ctx.log.warn("[fb-cmsg] Empty body for RUpload photo; nothing to save.")
            return

        # Guess extension from content-type or magic bytes
        ext = _guess_image_ext(ct, body[:64], "")
        out_path = outdir / f"{rid}_rupload_fb_photo.{ext}"

        with open(out_path, "wb") as f:
            f.write(body)

        ctx.log.info(f"[fb-cmsg] Saved RUpload raw image -> {out_path}")

        # (Optional) dump request headers for forensics
        hdr_path = outdir / f"{rid}_rupload_fb_photo.headers.txt"
        try:
            with open(hdr_path, "w", encoding="utf-8") as hf:
                for k, v in flow.request.headers.items(multi=True):
                    hf.write(f"{k}: {v}\n")
            ctx.log.info(f"[fb-cmsg] Saved headers -> {hdr_path}")
        except Exception as e:
            ctx.log.warn(f"[fb-cmsg] Could not save header dump: {e}")


    def _handle_photo_upload(self, flow: http.HTTPFlow) -> None:
        ctx.log.warn("why do you not see me...")
        outdir = Path(ctx.options.fb_photo_dir)
        _ensure_dir(outdir)

        rid = f"{_now_tag()}_{flow.id}"
        ctype_raw = flow.request.headers.get("content-type") or ""
        ctype_lc  = ctype_raw.lower()
        body = flow.request.get_content() or b""

        ctx.log.info(f"[fb-cmsg] Photo POST hit: {flow.request.pretty_url} (flow.id={flow.id})")
        ctx.log.info(f"[fb-cmsg] Content-Type='{ctype_raw}', Content-Length={flow.request.headers.get('content-length','?')}")

        saved = False

        # --- Multipart (preferred path) ---
        if "multipart/form-data" in ctype_lc:
            parts = list(_iter_multipart_parts(body, ctype_raw))
            ctx.log.info(f"[fb-cmsg] Photo multipart parts: {len(parts)}")
            for p in parts:
                name = p.get("name") or ""
                if name != "source":
                    continue
                payload: bytes = p.get("payload") or b""
                headers = p.get("headers") or {}
                ct = (headers.get("content-type") or "").lower()
                filename = p.get("filename") or ""
                ext = _guess_image_ext(ct, payload[:64], filename)
                out_path = outdir / f"{rid}_source.{ext}"
                with open(out_path, "wb") as f:
                    f.write(payload)
                ctx.log.info(f"[fb-cmsg] Saved photo source -> {out_path}")
                saved = True

            if not saved:
                ctx.log.warn("[fb-cmsg] No 'source' part found in multipart payload.")
            return

        # --- x-www-form-urlencoded ---
        if "application/x-www-form-urlencoded" in ctype_lc or b"source=" in body:
            try:
                params = _parse_form_bytes(body)
            except Exception as e:
                ctx.log.error(f"[fb-cmsg] Failed to parse photo form body: {e}")
                return

            vals = params.get("source", [])
            if not vals:
                ctx.log.warn("[fb-cmsg] Form has no 'source' field.")
                return

            # Typically only one 'source'
            raw = vals[0]

            # Try data URL
            decoded = _maybe_decode_data_url(raw)
            if decoded is None:
                # Try base64
                b64 = _try_base64(raw.decode("latin-1", "replace"))
                decoded = b64 if b64 is not None else raw  # keep as-is

            ext = _guess_image_ext(flow.request.headers.get("content-type","").lower(), decoded[:64], "")
            out_path = outdir / f"{rid}_source.{ext}"
            with open(out_path, "wb") as f:
                f.write(decoded)
            ctx.log.info(f"[fb-cmsg] Saved photo source -> {out_path}")
            return

        # --- Fallback: unknown content-type ---
        # As a last resort, dump whole body so nothing is lost.
        raw_path = outdir / f"{rid}_unknown_photo_body.bin"
        with open(raw_path, "wb") as f:
            f.write(body)
        ctx.log.warn(f"[fb-cmsg] Unknown photo upload Content-Type; saved raw body -> {raw_path}")


    def running(self):
        outdir = Path(ctx.options.fb_dump_dir)
        _ensure_dir(outdir)
        ctx.log.info(f"[fb-post_0] Output directory: {outdir.resolve()}")
        ctx.log.info(f"[fb-post_0] Preview limit: {ctx.options.fb_preview_chars} chars")
        ctx.log.info(f"[fb-post_0] Print mode: {ctx.options.fb_print_mode}")
        self._form_binary_keys_rx = re.compile(ctx.options.fb_form_binary_keys, re.I)
        ctx.log.info(f"[fb-cmsg] Form-binary-keys regex: {ctx.options.fb_form_binary_keys}")

    def request(self, flow: http.HTTPFlow):
        host = flow.request.host
        path = flow.request.path
        if flow.request.method.upper() != "POST":
            return


        # Recognizers
        is_photo = (host == GRAPH_HOST and PHOTO_PATH_RE.match(path) is not None)
        hostpath_in_targets = any(host == h and path.startswith(p) for (h, p) in TARGETS)
        is_rupload_photo = (host == "rupload.facebook.com" and path.startswith("/fb_photo/"))

        # If this flow is neither a known TARGET nor a photo upload, bail out
        if not (hostpath_in_targets or is_photo or is_rupload_photo):
            return


        outdir = Path(ctx.options.fb_dump_dir)
        _ensure_dir(outdir)

        if is_photo:
            self._handle_photo_upload(flow)
            return

        if is_rupload_photo:
            self._handle_rupload_photo(flow)
            return

        rid = f"{_now_tag()}_{flow.id}"
        ctype_raw = flow.request.headers.get("content-type") or ""   # RAW (keep case for boundary)
        ctype_lc  = ctype_raw.lower()
        clen = flow.request.headers.get("content-length", "?")
        enc = flow.request.headers.get("content-encoding", "")
        body = flow.request.get_content() or b""

        ctx.log.info(f"[fb-cmsg] Hit: {flow.request.method} {flow.request.pretty_url} (flow.id={flow.id})")
        ctx.log.info(f"[fb-cmsg] Content-Type='{ctype_raw}', Content-Length={clen}, Content-Encoding='{enc}'")

        mode = int(ctx.options.fb_print_mode)
        cmsgs: List[bytes] = []
        cmethod = ""

        # ---- FORM-ENCODED ----
        if "application/x-www-form-urlencoded" in ctype_lc or b"cmsg=" in body:
            try:
                params = _parse_form_bytes(body)
            except Exception as e:
                ctx.log.error(f"[fb-cmsg] Failed to parse form body: {e}")
                prev = _safe_text_preview(body, ctx.options.fb_preview_chars)
                ctx.log.info(f"[fb-cmsg] Body preview (form, UTF-8 best-effort):\n{prev}")
                return

            keys_preview = list(params.keys())[:10]
            ctx.log.info(f"[fb-cmsg] Form keys: {keys_preview}{' ...' if len(params.keys()) > 10 else ''}")

            cmsgs = params.get("cmsg", [])
            cmethod_vals = params.get("cmethod", [])
            cmethod = cmethod_vals[0].decode("latin-1", "ignore") if cmethod_vals else ""
            if cmsgs:
                ctx.log.info(f"[fb-cmsg] Found {len(cmsgs)} cmsg value(s) in form body; cmethod='{cmethod}'")
            else:
                ctx.log.warn("[fb-cmsg] 'cmsg' parameter missing in form body.")
                prev = _safe_text_preview(body, ctx.options.fb_preview_chars)
                ctx.log.info(f"[fb-cmsg] Body preview (form, UTF-8 best-effort):\n{prev}")


            extra_blobs: List[Tuple[str, bytes]] = []
            for k, vals in params.items():
                if self._form_binary_keys_rx.match(k) and k != "cmsg":
                    for vb in vals:
                        # vb is bytes thanks to _parse_form_bytes; try decompress-any
                        dec, algo = _decompress_any(vb if cmethod.lower() != "gzip" else gzip.decompress(vb))
                        extra_blobs.append((k, vb))
                        # Save both raw and decoded variants similar to cmsg-saving
                        suffix = f"{rid}_{k}"
                        # raw
                        raw_path = outdir / f"{suffix}.part.bin"
                        with open(raw_path, "wb") as f:
                            f.write(vb)
                        ctx.log.info(f"[fb-cmsg] Wrote raw form-part -> {raw_path}")
                        # hex
                        part_hex = outdir / f"{suffix}.hex"
                        _write_full_hexdump(part_hex, vb)
                        ctx.log.info(f"[fb-cmsg] Wrote hex dump     -> {part_hex}")
                        # decoded
                        algo_tag = algo
                        if algo in ("gzip","zlib","deflate"):
                            with open(outdir / f"{suffix}.raw_{algo}", "wb") as f:
                                f.write(vb)
                            ctx.log.info(f"[fb-cmsg] Wrote original {algo} -> {outdir / (suffix + '.raw_' + algo)}")
                        bin_path = outdir / f"{suffix}.bin"
                        with open(bin_path, "wb") as f:
                            f.write(dec)
                        ctx.log.info(f"[fb-cmsg] Decompressed({algo_tag}) bytes -> {bin_path}")

                        # try to pretty-print JSON and save .json if it parses
                        try:
                            txt = dec.decode("utf-8")
                            txts = txt.strip()
                            if (txts.startswith("{") and txts.endswith("}")) or (txts.startswith("[") and txts.endswith("]")):
                                obj = json.loads(txts)
                                json_path = outdir / f"{suffix}.json"
                                with open(json_path, "w", encoding="utf-8") as jf:
                                    json.dump(obj, jf, ensure_ascii=False, indent=2)
                                ctx.log.info(f"[fb-cmsg] Wrote JSON -> {json_path}")
                            else:
                                _save_text(outdir / f"{suffix}.txt", dec)
                                ctx.log.info(f"[fb-cmsg] Wrote text -> {outdir / (suffix + '.txt')}")
                        except Exception as e:
                            _save_text(outdir / f"{suffix}.txt", dec)
                            ctx.log.warn(f"Error in json: {e}")
                            ctx.log.info(f"[fb-cmsg] Wrote text -> {outdir / (suffix + '.txt')}")

            # If we found something here, we can return early (like we do for cmsgs)
            if extra_blobs:
                return

        # ---- JSON BODY (top-level) ----
        if not cmsgs and ("application/json" in ctype_lc or body.startswith(b"{") or body.startswith(b"[")):
            try:
                text = body.decode("utf-8", "replace")
                obj = json.loads(text)
            except Exception as e:
                ctx.log.error(f"[fb-cmsg] JSON parse failed: {e}")
                prev = _safe_text_preview(body, ctx.options.fb_preview_chars)
                ctx.log.info(f"[fb-cmsg] Body preview (JSON-ish, UTF-8 best-effort):\n{prev}")
                return

            # NEW: always save a pretty JSON for the whole body
            pretty = json.dumps(obj, indent=2, ensure_ascii=False)
            json_path = outdir / f"{rid}.json"
            with open(json_path, "w", encoding="utf-8") as f:
                f.write(pretty + "\n")
            ctx.log.info(f"[fb-cmsg] Wrote JSON  -> {json_path}")

            if isinstance(obj, dict):
                keys = list(obj.keys())
                ctx.log.info(f"[fb-cmsg] JSON object with keys: {keys[:20]}{' ...' if len(keys) > 20 else ''}")
            elif isinstance(obj, list):
                ctx.log.info(f"[fb-cmsg] JSON array length: {len(obj)}")
            else:
                ctx.log.info(f"[fb-cmsg] JSON top-level type: {type(obj).__name__}")

            found = _collect_cmsg_bytes_from_json(obj)
            if found:
                cmsgs = found
                ctx.log.info(f"[fb-cmsg] Found {len(cmsgs)} cmsg value(s) in JSON body.")
            else:
                ctx.log.warn("[fb-cmsg] JSON body present, but no 'cmsg' fields found.")
                # keep going; the pretty JSON is already saved

        # Handle cmsg blobs (form/JSON)
        if cmsgs:
            for i, raw in enumerate(cmsgs, start=1):
                suffix = f"{rid}_{i:02d}"
                ctx.log.info(f"[fb-cmsg] cmsg[{i}] length={len(raw)} bytes (pre-decompression)")
                _decompress_and_save(outdir, suffix, raw)
            return

        # ---- MULTIPART ----
        if "multipart/form-data" in ctype_lc:
            boundary = _parse_boundary_from_header(ctype_raw) or ""
            parts = list(_iter_multipart_parts(body, ctype_raw))
            ctx.log.info(f"[fb-cmsg] Multipart parts: {len(parts)}")

            if not parts:
                # Save whole body for debugging
                raw_path = outdir / f"{rid}.raw_body.bin"
                with open(raw_path, "wb") as f:
                    f.write(body)
                ctx.log.info(f"[fb-cmsg] Wrote raw body -> {raw_path}")

                if boundary:
                    blob = _heuristic_extract_first_binary_section(body, boundary)
                    if blob:
                        if mode == 2:
                            ctx.log.info("hexdump preview (heuristic binary section):")
                            ctx.log.info(_hexdump(blob, 256))
                        elif mode == 3:
                            dec = _decompress(blob)
                            # Try pretty JSON + save
                            if not _try_save_json(outdir, rid + ".heuristic", dec):
                                try:
                                    ctx.log.info(dec.decode("utf-8"))
                                except Exception:
                                    ctx.log.info(_hexdump(dec, 256))
                        out_path = outdir / f"{rid}.raw_binary_body.bin"
                        with open(out_path, "wb") as f:
                            f.write(blob)
                        ctx.log.info(f"[fb-cmsg] Wrote raw binary section -> {out_path}")
                return

            # Print multipart view (modes 2/3)
            if mode in (2, 3):
                _print_multipart_view(boundary, parts, mode)

            # Save per-part + combined + decodes
            combined_binary: List[bytes] = []
            for part in parts:
                idx = part["idx"]; name = part["name"] or f"part{idx}"
                ct = part["ct"]; cte = part["cte"]; payload = part["payload"]

                # Binary preview/files for mode 1 too
                if cte == "binary" or (ct == "application/octet-stream" and payload):
                    if mode == 1:
                        ctx.log.info(f"[fb-cmsg] Part {idx} hexdump preview:\n{_hexdump(payload, 256)}")

                    part_bin = outdir / f"{rid}_{idx:02d}_{name}.part.bin"
                    with open(part_bin, "wb") as f:
                        f.write(payload)
                    ctx.log.info(f"[fb-cmsg] Wrote raw part bytes -> {part_bin}")

                    part_hex = outdir / f"{rid}_{idx:02d}_{name}.hex"
                    _write_full_hexdump(part_hex, payload)
                    ctx.log.info(f"[fb-cmsg] Wrote hex dump       -> {part_hex}")

                    combined_binary.append(payload)

                # cmsg convenience path (decode + save + JSON pretty)
                if name == "cmsg":
                    _decompress_and_save(outdir, f"{rid}_{idx:02d}_{name}", payload)
                elif ct == "application/octet-stream" and payload:
                    # if gzipped, _decompress_and_save will also try JSON
                    _decompress_and_save(outdir, f"{rid}_{idx:02d}_{name or 'octet'}", payload)
                elif ct.startswith("application/json"):
                    # direct JSON part (rare)
                    suffix = f"{rid}_{idx:02d}_{name or 'json'}"
                    # save raw text and pretty json
                    _save_text(outdir / f"{suffix}.txt", payload)
                    if not _try_save_json(outdir, suffix, payload):
                        ctx.log.info(f"[fb-cmsg] JSON part {idx} not valid JSON (?)")

            if combined_binary:
                combined_path = outdir / f"{rid}.raw_binary_body.bin"
                with open(combined_path, "wb") as f:
                    for seg in combined_binary:
                        f.write(seg)
                ctx.log.info(f"[fb-cmsg] Wrote combined binary -> {combined_path}")
            return

        # Fallback
        ctx.log.warn("[fb-cmsg] No cmsg found; unsupported content-type or body format.")
        prev = _safe_text_preview(body, ctx.options.fb_preview_chars)
        ctx.log.info(f"[fb-cmsg] FINAL body preview (UTF-8 best-effort):\n{prev}")

addons = [FbCmsgDumper()]
