# yara\_vt\_mock

This YARA module implements the same interface as the [VirusTotal vt YARA module](https://support.virustotal.com/hc/en-us/articles/360007088057-Writing-YARA-rules-for-Livehunt), making it possible to test livehunt rules against local files outside of a livehunt context.

To do that, a JSON file of metadata has to be supplied to the module, from which it extracts the necessary information to present the same interface as the VT module would.

## Example usage

Suppose we have written the following (somewhat contrived) livehunt rule:

```
$ cat livehunt.yara
import "vt"

rule mock_test
{
    condition:
        vt.metadata.new_file
        and vt.metadata.exiftool["MIMEType"] == "application/msword"
        and for any tag in vt.metadata.tags : (
            tag == "macros"
        )
        and vt.metadata.signatures["Microsoft"] == "Trojan:O97M/Sadoca.C!ml"
        and vt.metadata.file_type == vt.FileType.DOC
        and for any tag in vt.metadata.file_type_tags : (
            tag == "msoffice"
        )
        and vt.metadata.magic contains "CDF V2 Document"
        and vt.metadata.submitter.country == "MX"
        and vt.metadata.submitter.city contains "mexico"
}
```

Using the included utility script we fetch all necessary metadata into `/tmp/meta.json` and can then simply call:

```
$ yara -x vt=/tmp/meta.json livehunt.yara /tmp/testfile
mock_test /tmp/testfile
```

This way we can easily debug livehunt rules against certain files without having to wait for hits on a real livehunt.

## Installation

Fetch the source repos:

```bash
git clone https://github.com/VirusTotal/yara
git clone https://github.com/usualsuspect/yara_vt_mock
```

Then use the included script to integrate this module into the YARA repository:

```bash
yara_vt_mock/integrate.sh /path/to/yara/repo
```

Then build YARA. We need to include the cuckoo module so we get access to the Jansson JSON library (the cuckoo module has build magic for it already).

At the time of writing (2022-02-07), this would be:

```bash
cd yara
./bootstrap.sh
./configure --enable-cuckoo
make
```

If all went well, you should have a `yara` binary in the YARA repository with this module included.

## Usage

If you want to test a livehunt YARA rule against a given file, you need to fetch the file's metadata first. For that you can use the included `fetch_metadata.py` script (requires `vt` Python module).

Edit in your VirusTotal API key, then let it fetch the necessary metadata:

```
$ fetch_metadata.py <some SHA256> > /tmp/meta.json
```

Then simply call:

```bash
$ yara -x vt=/tmp/meta.json somerule.yara somefile
```

## Coverage

The module currently supports the complete `vt.metadata.*` namespace.

`vt.behaviour.*` might come at a later date.

### Notes

#### vt.metadata.new\_file

Livehunt rules are executed on a submission basis, where it's clear if a file is new or not. This module tries to emulate this behaviour by checking if the `first_submission_date` and `last_submission_date` are the same. However, for debugging purposes it of course might make sense to always set `vt.metadata.new_file`. If this is desired, replace the following line of code in `vt.c`:

```c
set_integer(first_sub == last_sub,module_object,"metadata.new_file");
```

with

```c
set_integer(1,module_object,"metadata.new_file");
```

This way you can freely test your rules even if the target file was submitted multiple times.

#### vt.submitter.*

As livehunts are called on a submission basis, there is only one possible value for the submitter. In our case though, we might get a list of submissions if a file has been submitted multiple times. This module uses the first entry (and thus latest submission) to fill the `vt.submitter.*` structure.
