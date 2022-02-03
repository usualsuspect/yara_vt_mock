# yara_vt_mock

This YARA module implement the same interface as the [VirusTotal vt YARA module](https://support.virustotal.com/hc/en-us/articles/360007088057-Writing-YARA-rules-for-Livehunt), making it possible to test livehunt rules against local files.

# Coverage

The module currently supports all of the `vt.metadata.*` namespace. `vt.behaviour.*` might come at a later date.

## Notes

### vt.metadata.new_file

Livehunt rules are executed on a submission basis, where it's clear if a file is new or not. This module tries to emulate this behaviour by checking if the `first_submission_date` and `last_submission_date` are the same. However, for debugging purposes it of course might make sense to always set `vt.metadata.new_file`. If this is desired, replace the following line of code in `vt.c`:

```c
set_integer(first_sub == last_sub,module_object,"metadata.new_file");
```

with

```c
set_integer(1,module_object,"metadata.new_file");
```

This way you can freely test your rules even if the target file was submitted multiple times.
