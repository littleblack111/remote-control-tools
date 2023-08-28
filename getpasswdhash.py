#!/usr/bin/env python3

"""
Mac OSX Catalina User Password Hash Extractor

Extracts a user's password hash as a hashcat-compatible string.

Mac OSX Catalina (10.15) uses a salted SHA-512 PBKDF2 for storing user passwords
(hashcat type 7100), and it's saved in an annoying binary-plist-nested-inside-xml-plist
format, so previously reported methods for extracting the hash don't work.


** You must be root to do this. **


Example Usage:

  sudo ./osx_hash_extract.py <username> > hash.txt
  hashcat -a 0 -m 7100 --username hash.txt wordlist.dat

"""

import plistlib
import sys


def read_user_plist(username):
    plist_path = f"/var/db/dslocal/nodes/Default/users/{username}.plist"
    with open(plist_path, "rb") as f:
        plist = plistlib.load(f)

    return plist

def extract_shadow_hash(user_plist):
    # Nested binary plist
    nested_bplist = user_plist["ShadowHashData"]
    shadow_hash_plist = plistlib.loads(nested_bplist[0])

    shadow = shadow_hash_plist["SALTED-SHA512-PBKDF2"]

    pbkdf2 = {"iterations": shadow["iterations"],
              "entropy": shadow["entropy"][:64].hex(), # Only the first 512 bits
              "salt": shadow["salt"].hex()}

    return pbkdf2

def format_hashcat(username, pbkdf2):
    hc_line = f"{username}:$ml${pbkdf2['iterations']}${pbkdf2['salt']}${pbkdf2['entropy']}"
    return hc_line



def main(args):
    username = args[1]
    user_plist = read_user_plist(username)
    shadow = extract_shadow_hash(user_plist)
    hc_input = format_hashcat(username, shadow)
    print(hc_input)


if __name__ == "__main__":
    main(sys.argv)
