#!/usr/bin/env python3
import vt
import re
import sys
import json

VT_API_KEY = ""

def main():
    client = vt.Client(VT_API_KEY)

    sha256_pat = "\\b[a-fA-F0-9]{64}\\b"
    if not re.match(sha256_pat,sys.argv[1]):
        print("Not a SHA256 sum")
        sysi.exit(1)

    file_info = client.get_json("/files/%s" % sys.argv[1])

    # now get submission info
    sub_info = client.get_json("/files/%s/submissions" % (sys.argv[1]))
    client.close()

    file_info["data"]["attributes"]["submitter"] = {'country':sub_info["data"][0]["attributes"]["country"], 'city':sub_info["data"][0]["attributes"]["city"]}
    print(json.dumps(file_info,indent=4))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: %s <SHA256 sum>" % sys.argv[0])
        sys.exit(1)
    if VT_API_KEY == "":
        print("You forgot to set your API key!")
        sys.exit(1)
    main()
