# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Encrypting files with 7zip
# RTA: sevenzip_encrypted.py
# ATT&CK: T1022
# Description: Uses "bin\.exe" to perform encryption of archives and archive headers.

import base64
import os
import sys

from . import common

SEVENZIP = common.get_path("bin", "7za.exe")


def create_exfil(path=os.path.abspath("secret_stuff.txt")):
    common.log(f"Writing dummy exfil to {path}")
    with open(path, 'wb') as f:
        f.write(base64.b64encode(b"This is really secret stuff\n" * 100))
    return path


@common.requires_os(common.WINDOWS)
@common.dependencies(SEVENZIP)
def main(password="s0l33t"):
    # create 7z.exe with not-7zip name, and exfil
    svnz2 = os.path.abspath("a.exe")
    common.copy_file(SEVENZIP, svnz2)
    exfil = create_exfil()

    exts = ["7z", "zip", "gzip", "tar", "bz2", "bzip2", "xz"]
    out_jpg = os.path.abspath("out.jpg")

    for ext in exts:
        # Write archive for each type
        out_file = os.path.abspath(f"out.{ext}")
        common.execute([svnz2, "a", out_file, f"-p{password}", exfil], mute=True)
        common.remove_file(out_file)

        # Write archive for each type with -t flag
        if ext == "bz2":
            continue

        common.execute(
            [svnz2, "a", out_jpg, f"-p{password}", f"-t{ext}", exfil],
            mute=True,
        )

        common.remove_file(out_jpg)

    common.execute([SEVENZIP, "a", out_jpg, f"-p{password}", exfil], mute=True)
    common.remove_files(exfil, svnz2, out_jpg)


if __name__ == "__main__":
    exit(main(*sys.argv[1:]))
