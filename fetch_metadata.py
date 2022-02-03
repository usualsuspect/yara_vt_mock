#!/usr/bin/env python3
import vt
import re
import sys
import json
import argparse

VT_API_KEY = ""

def hash_file(fname):
    h = []
    with open(fname,"r") as f:
        for line in f:
            h.append(line.strip())
    return ",".join(h)


def init_args():
    return None

def main(args):
    client = vt.Client(VT_API_KEY)

    sha256_pat = "\\b[a-fA-F0-9]{64}\\b"
    if not re.match(sha256_pat,sys.argv[1]):
        print("Need a SHA256 sum")
        sysi.exit(0)

    file_info = client.get_json("/files/%s" % sys.argv[1])

    # now get submission info
    sub_info = client.get_json("/files/%s/submissions" % (sys.argv[1]))
    client.close()

    file_info["data"]["attributes"]["submitter"] = {'country':sub_info["data"][0]["attributes"]["country"], 'city':sub_info["data"][0]["attributes"]["city"]}
    print(json.dumps(file_info,indent=4))

if __name__ == "__main__":
    args = init_args()
    main(args)
