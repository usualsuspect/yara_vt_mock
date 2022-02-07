import "vt"

rule test_metadata_analysis_stats
{
    condition:
        vt.metadata.analysis_stats.malicious == 16
        and vt.metadata.analysis_stats.undetected == 51
        and vt.metadata.analysis_stats.failure == 0
        and vt.metadata.analysis_stats.type_unsupported == 4
}

rule test_metadata_exiftool
{
    condition:
        vt.metadata.exiftool["MIMEType"] == "application/octet-stream"
        and vt.metadata.exiftool["EntryPoint"] == "0xc27bf8"
}

rule test_metadata_first_submission_date
{
    condition:
        vt.metadata.first_submission_date == 1644198754
}

rule test_metadata_file_name
{
    condition:
        vt.metadata.file_name == "/tmp/cache/extracted_files/916e420650f2d172b5e366d7829628d415135c3a.bin"
}

rule test_metadata_file_size
{
    condition:
        vt.metadata.file_size == 8604312
}

rule test_metadata_file_type
{
    condition:
        vt.metadata.file_type == vt.FileType.PE_EXE
}

rule test_metadata_file_type_tags
{
    condition:
        for any tag in vt.metadata.file_type_tags : ( tag == "executable" )
        and for any tag in vt.metadata.file_type_tags : ( tag == "windows" )
        and for any tag in vt.metadata.file_type_tags : ( tag == "win32" )
        and for any tag in vt.metadata.file_type_tags : ( tag == "pe" )
        and for any tag in vt.metadata.file_type_tags : ( tag == "peexe" )
}

rule test_metadata_imphash
{
    condition:
        vt.metadata.imphash == "22590512994df9e6d22bf24a16aae00d"
}

rule test_metadata_new_file
{
    condition:
        vt.metadata.new_file
}

rule test_metadata_magic
{
    condition:
        vt.metadata.magic == "PE32+ executable for MS Windows (console) Mono/.Net assembly"
}

/*
    file has no icon
rule test_metadata_mainicon
{
    condition:
        vt.metadata.main_icon.dhash == ""
        and vt.metadata.main_icon.md5 == ""
}
*/

rule test_metadata_md5
{
    condition:
        vt.metadata.md5 == "cf9c9f4b71f8aa83c36f086040f30721"
}

rule test_metadata_sha256
{
    condition:
        vt.metadata.sha256 == "5db36018cf9c030d5aedf030de29e1f307552cf64bc598e0dc00253f572142ce"
}

rule test_metadata_sha1
{
    condition:
        vt.metadata.sha1 == "916e420650f2d172b5e366d7829628d415135c3a"
}

rule test_metadata_signatures
{
    condition:
        for any engine, signature in vt.metadata.signatures : (
            engine == "Kaspersky" and signature == "Backdoor.Win32.Androm.vahe"
        )
}

rule test_metadata_ssdeep
{
    condition:
        vt.metadata.ssdeep == "196608:ZzSWXaWcuAuLfCfvIp3D6VJLosYFz6txopwuBn+fItx/yl:kt3IxCqBuxcn+gLq"
}

rule test_metadata_subfile
{
    condition:
        vt.metadata.subfile == 0
}

rule test_metadata_submitter
{
    condition:
        vt.metadata.submitter.city == "bochum"
        and vt.metadata.submitter.country == "DE"
}

rule test_metadata_tags
{
    condition:
        for any tag in vt.metadata.tags : ( tag == "peexe")
        and for any tag in vt.metadata.tags : ( tag == "assembly")
        and for any tag in vt.metadata.tags : ( tag == "overlay")
        and for any tag in vt.metadata.tags : ( tag == "signed")
        and for any tag in vt.metadata.tags : ( tag == "64bits")
        and for any tag in vt.metadata.tags : ( tag == "invalid-signature")
}

rule test_metadata_all
{
    condition:
        test_metadata_analysis_stats
        and test_metadata_exiftool
        and test_metadata_first_submission_date
        and test_metadata_file_name
        and test_metadata_file_size
        and test_metadata_file_type
        and test_metadata_file_type_tags
        and test_metadata_imphash
        and test_metadata_new_file
        and test_metadata_magic
        and test_metadata_md5
        and test_metadata_sha256
        and test_metadata_sha1
        and test_metadata_signatures
        and test_metadata_ssdeep
        and test_metadata_subfile
        and test_metadata_submitter
        and test_metadata_tags
}
