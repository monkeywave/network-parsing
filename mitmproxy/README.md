# Scripts for parsing MITM-Proxy Traffic

Invoke it via `mitmdump`. You can set the following:
- `--set fb_dump_dir`: sets the output directory for json files and other gziped files as hex
- `--set fb_print_mode=<n>`: Traffic Print mode: 1=concise (default), 2=multipart view + hexdump for binary, 3=plain decoded + JSON pretty.
- `fb_photo_dir`: sets the output directory for image files
```bash
mitmdump -nr prepare_post_discard_save_as_draft.mitm -s deflate_fb_traffic.py --set fb_dump_dir=./draf1 --set fb_print_mode=3
```