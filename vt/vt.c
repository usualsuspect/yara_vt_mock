#include <yara/modules.h>
#include <stdio.h>
#include <stdlib.h>

#include <jansson.h>
#include "type_mapping.h"

#define MODULE_NAME vt

//debug build currently (2022-02-07) broken in the YARA repo, workaround for debugging
#define YR_DEBUG_FPRINTF dbg_print

void dbg_print(int bla,FILE *stream, const char *fmt,...)
{
    va_list ptr;
    va_start(ptr,fmt);
    vfprintf(stream,fmt,ptr);
    va_end(ptr);
}

begin_declarations;
    begin_struct("metadata");
        begin_struct("analysis_stats");
            declare_integer("malicious")
            declare_integer("undetected")
            declare_integer("failure")
            declare_integer("type_unsupported")
        end_struct("analysis_stats");

        declare_string_dictionary("exiftool");
        declare_integer("first_submission_date");
        declare_string("file_name");
        declare_integer("file_size");
        declare_integer("file_type");
        declare_string_array("file_type_tags");
        declare_string("imphash");
        declare_integer("new_file");
        declare_string("magic");

        begin_struct("main_icon");
            declare_string("dhash");
            declare_string("raw_md5");
        end_struct("main_icon");

        declare_string("md5");
        declare_string("sha256");
        declare_string("sha1");
        declare_string_dictionary("signatures");
        declare_string("ssdeep");
        declare_integer("subfile");

        begin_struct("submitter");
            declare_string("city");
            declare_string("country");
        end_struct("submitter");

        declare_string_array("tags");
        declare_integer("times_submitted");
        declare_integer("unique_sources");
        declare_string("vhash");
    end_struct("metadata");

    begin_struct("FileType");
        declare_integer("ACE");
        declare_integer("ANDROID");
        declare_integer("APPLE");
        declare_integer("APPLE_PLIST");
        declare_integer("APPLEDOUBLE");
        declare_integer("APPLESINGLE");
        declare_integer("ARC");
        declare_integer("ARJ");
        declare_integer("ASD");
        declare_integer("ASF");
        declare_integer("AVI");
        declare_integer("AWK");
        declare_integer("BMP");
        declare_integer("BZIP");
        declare_integer("C");
        declare_integer("CAB");
        declare_integer("CAP");
        declare_integer("CHM");
        declare_integer("COFF");
        declare_integer("COOKIE");
        declare_integer("CPP");
        declare_integer("CRX");
        declare_integer("DEB");
        declare_integer("DIB");
        declare_integer("DIVX");
        declare_integer("DMG");
        declare_integer("DOC");
        declare_integer("DOCX");
        declare_integer("DOS_COM");
        declare_integer("DOS_EXE");
        declare_integer("DYALOG");
        declare_integer("DZIP");
        declare_integer("EBOOK");
        declare_integer("ELF");
        declare_integer("EMAIL");
        declare_integer("EMF");
        declare_integer("EOT");
        declare_integer("FLAC");
        declare_integer("FLC");
        declare_integer("FLI");
        declare_integer("FLV");
        declare_integer("FORTRAN");
        declare_integer("FPX");
        declare_integer("GIF");
        declare_integer("GIMP");
        declare_integer("GUL");
        declare_integer("GZIP");
        declare_integer("HTML");
        declare_integer("HWP");
        declare_integer("ICO");
        declare_integer("IN_DESIGN");
        declare_integer("IPHONE");
        declare_integer("ISOIMAGE");
        declare_integer("JAR");
        declare_integer("JAVA");
        declare_integer("JAVA_BYTECODE");
        declare_integer("JAVASCRIPT");
        declare_integer("JNG");
        declare_integer("JPEG");
        declare_integer("KGB");
        declare_integer("LATEX");
        declare_integer("LINUX");
        declare_integer("LINUX_KERNEL");
        declare_integer("LNK");
        declare_integer("MACH_O");
        declare_integer("MACINTOSH");
        declare_integer("MACINTOSH_HFS");
        declare_integer("MACINTOSH_LIB");
        declare_integer("MIDI");
        declare_integer("MOV");
        declare_integer("MP3");
        declare_integer("MP4");
        declare_integer("MPEG");
        declare_integer("MSCOMPRESS");
        declare_integer("MSI");
        declare_integer("NE_DLL");
        declare_integer("NE_EXE");
        declare_integer("ODF");
        declare_integer("ODG");
        declare_integer("ODP");
        declare_integer("ODS");
        declare_integer("ODT");
        declare_integer("OGG");
        declare_integer("OUTLOOK");
        declare_integer("PALMOS");
        declare_integer("PASCAL");
        declare_integer("PDF");
        declare_integer("PE_DLL");
        declare_integer("PE_EXE");
        declare_integer("PERL");
        declare_integer("PHP");
        declare_integer("PKG");
        declare_integer("PNG");
        declare_integer("PPSX");
        declare_integer("PPT");
        declare_integer("PPTX");
        declare_integer("PS");
        declare_integer("PSD");
        declare_integer("PYTHON");
        declare_integer("QUICKTIME");
        declare_integer("RAR");
        declare_integer("RM");
        declare_integer("ROM");
        declare_integer("RPM");
        declare_integer("RTF");
        declare_integer("RUBY");
        declare_integer("RZIP");
        declare_integer("SCRIPT");
        declare_integer("SEVENZIP");
        declare_integer("SHELLSCRIPT");
        declare_integer("SVG");
        declare_integer("SWF");
        declare_integer("SYMBIAN");
        declare_integer("T3GP");
        declare_integer("TAR");
        declare_integer("TARGA");
        declare_integer("TEXT");
        declare_integer("TIFF");
        declare_integer("TORRENT");
        declare_integer("TTF");
        declare_integer("WAV");
        declare_integer("WINCE");
        declare_integer("WMA");
        declare_integer("WMV");
        declare_integer("WOFF");
        declare_integer("XLS");
        declare_integer("XLSX");
        declare_integer("XML");
        declare_integer("XPI");
        declare_integer("XWD");
        declare_integer("ZIP");
        declare_integer("ZLIB");
    end_struct("FileType");
end_declarations;

int module_initialize(YR_MODULE *module)
{
    YR_DEBUG_FPRINTF(1, stderr, "%s", "module_initialize\n");
    return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE *module)
{
    YR_DEBUG_FPRINTF(1, stderr, "%s", "module_finalize\n");
    return ERROR_SUCCESS;
}

void transfer_string(json_t *obj, YR_OBJECT *module_object, const char *source_name, const char *dest_name)
{
    if (!obj)
    {
        YR_DEBUG_FPRINTF(1, stderr, "transfer_string(%s,%s) called on nullptr\n", source_name, dest_name);
        return;
    }
    if (!json_is_object(obj))
    {
        YR_DEBUG_FPRINTF(1, stderr, "%s", "transfer_string called on non-object\n");
        return;
    }
    json_t *val = json_object_get(obj, source_name);
    if (!val)
    {
        YR_DEBUG_FPRINTF(1, stderr, "transfer_string - source %s not found\n", source_name);
        return;
    }

    if (!json_is_string(val))
    {
        YR_DEBUG_FPRINTF(1, stderr, "transfer_string - source %s not a string\n", source_name);
        return;
    }

    const char *valstring = json_string_value(val);
    set_string(valstring, module_object, dest_name);
}

void transfer_int(json_t *obj, YR_OBJECT *module_object, const char *source_name, const char *dest_name)
{
    if (!obj)
    {
        YR_DEBUG_FPRINTF(1, stderr, "transfer_int(%s,%s) called on nullptr\n", source_name, dest_name);
        return;
    }
    if (!json_is_object(obj))
    {
        YR_DEBUG_FPRINTF(1, stderr, "%s", "transfer_int called on non-object\n");
        return;
    }
    json_t *val = json_object_get(obj, source_name);
    if (!val)
    {
        YR_DEBUG_FPRINTF(1, stderr, "transfer_int - source %s not found\n", source_name);
        return;
    }

    int value = 0;
    if(json_is_real(val))
    {
        value = (int)json_real_value(val);
    }
    else if(json_is_integer(val))
    {
        value = json_integer_value(val);
    }
    else
    {
        YR_DEBUG_FPRINTF(1, stderr, "transfer_int - source %s not an integer/real\n", source_name);
    }
    set_integer(value, module_object, dest_name);
}

int safe_get_integer(json_t *obj, const char *valname)
{
    if (!obj)
    {
        YR_DEBUG_FPRINTF(1, stderr, "%s", "safe_get_integer called on nullptr\n");
        return 0;
    }
    json_t *val = json_object_get(obj, valname);
    if (!val)
    {
        YR_DEBUG_FPRINTF(1, stderr, "safe_get_integer - value %s not found\n", valname);
        return 0;
    }
    if(json_is_real(val))
    {
        return (int)json_real_value(val);
    }
    else if(json_is_integer(val))
    {
        return json_integer_value(val);
    }
    else
    {
        YR_DEBUG_FPRINTF(1,stderr,"safe_get_integer %s is not int/real\n",valname); 
        return 0;
    }
}

const char *safe_get_string(json_t *obj, const char *valname)
{
    if(!obj)
    {
        YR_DEBUG_FPRINTF(1,stderr, "safe_get_string(%s) called on nullptr\n",valname);
        return NULL;
    }
    json_t *val = json_object_get(obj,valname);
    if(!json_is_string(val))
    {
        YR_DEBUG_FPRINTF(1,stderr, "safe_get_string(%s) called on non-string\n",valname);
        return NULL;
    }
    return json_string_value(val);
}

int parse_vt_json(YR_OBJECT *module_object, char *json_data, size_t json_data_len)
{
    json_error_t err;
    json_t *root = json_loads(json_data, json_data_len, &err);
    if (!root)
    {
        YR_DEBUG_FPRINTF(1, stderr, "%s", "Parsing JSON data failed\n");
        return 1;
    }

    json_t *data = json_object_get(root, "data");
    if (!data)
    {
        YR_DEBUG_FPRINTF(1, stderr, "%s", "No data object in JSON");
        json_decref(root);
        return 1;
    }

    json_t *attributes = json_object_get(data, "attributes");
    if (!attributes)
    {
        YR_DEBUG_FPRINTF(1, stderr, "%s", "No attributes object in JSON");
        json_decref(root);
        return 1;
    }

    // metadata.analysis_stats
    json_t *analysis_stats = json_object_get(attributes, "last_analysis_stats");
    if (analysis_stats)
    {
        transfer_int(analysis_stats, module_object, "malicious", "metadata.analysis_stats.malicious");
        transfer_int(analysis_stats, module_object, "undetected", "metadata.analysis_stats.undetected");
        transfer_int(analysis_stats, module_object, "failure", "metadata.analysis_stats.failure");
        transfer_int(analysis_stats, module_object, "type-unsupported", "metadata.analysis_stats.type_unsupported");
    }

    // metadata.exiftool
    json_t *exiftool = json_object_get(attributes, "exiftool");
    if (exiftool)
    {
        const char *key;
        json_t *val;

        json_object_foreach(exiftool, key, val)
        {
            if (json_is_string(val))
            {
                set_string(json_string_value(val), module_object, "metadata.exiftool[%s]", key);
            }
        }
    }

    transfer_int(attributes, module_object, "first_submission_date", "metadata.first_submission_date");
    transfer_string(attributes,module_object,"meaningful_name","metadata.file_name");
    transfer_int(attributes,module_object,"size","metadata.file_size");
    transfer_string(attributes, module_object, "md5", "metadata.md5");
    transfer_string(attributes, module_object, "sha1", "metadata.sha1");
    transfer_string(attributes, module_object, "sha256", "metadata.sha256");
    transfer_string(attributes, module_object, "ssdeep", "metadata.ssdeep");
    
    transfer_string(attributes, module_object, "vhash", "metadata.vhash");
    transfer_string(attributes, module_object, "magic", "metadata.magic");

    // metadata.imphash
    json_t *pe_info = json_object_get(attributes, "pe_info");
    if(pe_info)
    {
        transfer_string(pe_info,module_object,"imphash","metadata.imphash");
    }

    transfer_int(attributes,module_object,"times_submitted","metadata.times_submitted");
    transfer_int(attributes,module_object,"unique_sources","metadata.unique_sources");

    // metadata.subfile - always set to false
    set_integer(0, module_object, "metadata.subfile");

    // metadata.new_file
    int first_sub = safe_get_integer(attributes, "first_submission_date");
    int last_sub = safe_get_integer(attributes, "last_submission_date");
    set_integer(first_sub == last_sub, module_object, "metadata.new_file");

    // metadata.main_icon
    json_t *main_icon = json_object_get(attributes, "main_icon");
    if (main_icon)
    {
        transfer_string(main_icon, module_object, "raw_md5", "metadata.main_icon.raw_md5");
        transfer_string(main_icon, module_object, "dhash", "metadata.main_icon.dhash");
    }

    // metadata.tags
    json_t *tags = json_object_get(attributes,"tags");
    if(tags && json_is_array(tags))
    {
        for(int i = 0; i < json_array_size(tags); ++i)
        {
            json_t *tag = json_array_get(tags,i);
            if (tag && json_is_string(tag))
            {
                const char *tag_string = json_string_value(tag);
                if (tag_string)
                {
                    set_string(tag_string,module_object,"metadata.tags[%i]",i);
                }
            }
        }
    }

    // metadata.signatures
    json_t *last_analysis_results = json_object_get(attributes,"last_analysis_results");
    if(last_analysis_results && json_is_object(last_analysis_results))
    {
        const char *avname;
        json_t *val;

        json_object_foreach(last_analysis_results,avname,val)
        {
            const char *res = safe_get_string(val,"result");
            if(res)
            {
                set_string(res,module_object,"metadata.signatures[%s]",avname);
            }
        }
    }

    // metadata.submitter
    json_t *submitter = json_object_get(attributes,"submitter");
    if(submitter)
    {
        transfer_string(submitter,module_object,"country","metadata.submitter.country");
        transfer_string(submitter,module_object,"city","metadata.submitter.city");
    }

    // metadata.file_type
    // lookup json["type_tag"] in our mapping struct
    const char *type_tag = safe_get_string(attributes,"type_tag");
    for (size_t i = 0; i < sizeof(type_mapping) / sizeof(type_mapping[0]); ++i)
    {
        if (!strcmp(type_tag, type_mapping[i][0]))
        {
            set_integer(i, module_object, "metadata.file_type");

            // now apply the respective file type tags
            for (int n = 1; n < sizeof(type_mapping[i]) / sizeof(char *); ++n)
            {
                if (type_mapping[i][n])
                {
                    YR_DEBUG_FPRINTF(1, stderr, "Adding type tag [%s]\n", type_mapping[i][n]);
                    set_string(type_mapping[i][n], module_object, "metadata.file_type_tags[%i]", n);
                }
            }
            break;
        }
    }

    json_decref(root);
    return 0;
}

void setup_constants(YR_OBJECT *module_object)
{
    set_integer(0, module_object, "FileType.ACE");
    set_integer(1, module_object, "FileType.ANDROID");
    set_integer(2, module_object, "FileType.APPLE");
    set_integer(3, module_object, "FileType.APPLE_PLIST");
    set_integer(4, module_object, "FileType.APPLEDOUBLE");
    set_integer(5, module_object, "FileType.APPLESINGLE");
    set_integer(6, module_object, "FileType.ARC");
    set_integer(7, module_object, "FileType.ARJ");
    set_integer(8, module_object, "FileType.ASD");
    set_integer(9, module_object, "FileType.ASF");
    set_integer(10, module_object, "FileType.AVI");
    set_integer(11, module_object, "FileType.AWK");
    set_integer(12, module_object, "FileType.BMP");
    set_integer(13, module_object, "FileType.BZIP");
    set_integer(14, module_object, "FileType.C");
    set_integer(15, module_object, "FileType.CAB");
    set_integer(16, module_object, "FileType.CAP");
    set_integer(17, module_object, "FileType.CHM");
    set_integer(18, module_object, "FileType.COFF");
    set_integer(19, module_object, "FileType.COOKIE");
    set_integer(20, module_object, "FileType.CPP");
    set_integer(21, module_object, "FileType.CRX");
    set_integer(22, module_object, "FileType.DEB");
    set_integer(23, module_object, "FileType.DIB");
    set_integer(24, module_object, "FileType.DIVX");
    set_integer(25, module_object, "FileType.DMG");
    set_integer(26, module_object, "FileType.DOC");
    set_integer(27, module_object, "FileType.DOCX");
    set_integer(28, module_object, "FileType.DOS_COM");
    set_integer(29, module_object, "FileType.DOS_EXE");
    set_integer(30, module_object, "FileType.DYALOG");
    set_integer(31, module_object, "FileType.DZIP");
    set_integer(32, module_object, "FileType.EBOOK");
    set_integer(33, module_object, "FileType.ELF");
    set_integer(34, module_object, "FileType.EMAIL");
    set_integer(35, module_object, "FileType.EMF");
    set_integer(36, module_object, "FileType.EOT");
    set_integer(37, module_object, "FileType.FLAC");
    set_integer(38, module_object, "FileType.FLC");
    set_integer(39, module_object, "FileType.FLI");
    set_integer(40, module_object, "FileType.FLV");
    set_integer(41, module_object, "FileType.FORTRAN");
    set_integer(42, module_object, "FileType.FPX");
    set_integer(43, module_object, "FileType.GIF");
    set_integer(44, module_object, "FileType.GIMP");
    set_integer(45, module_object, "FileType.GUL");
    set_integer(46, module_object, "FileType.GZIP");
    set_integer(47, module_object, "FileType.HTML");
    set_integer(48, module_object, "FileType.HWP");
    set_integer(49, module_object, "FileType.ICO");
    set_integer(50, module_object, "FileType.IN_DESIGN");
    set_integer(51, module_object, "FileType.IPHONE");
    set_integer(52, module_object, "FileType.ISOIMAGE");
    set_integer(53, module_object, "FileType.JAR");
    set_integer(54, module_object, "FileType.JAVA");
    set_integer(55, module_object, "FileType.JAVA_BYTECODE");
    set_integer(56, module_object, "FileType.JAVASCRIPT");
    set_integer(57, module_object, "FileType.JNG");
    set_integer(58, module_object, "FileType.JPEG");
    set_integer(59, module_object, "FileType.KGB");
    set_integer(60, module_object, "FileType.LATEX");
    set_integer(61, module_object, "FileType.LINUX");
    set_integer(62, module_object, "FileType.LINUX_KERNEL");
    set_integer(63, module_object, "FileType.LNK");
    set_integer(64, module_object, "FileType.MACH_O");
    set_integer(65, module_object, "FileType.MACINTOSH");
    set_integer(66, module_object, "FileType.MACINTOSH_HFS");
    set_integer(67, module_object, "FileType.MACINTOSH_LIB");
    set_integer(68, module_object, "FileType.MIDI");
    set_integer(69, module_object, "FileType.MOV");
    set_integer(70, module_object, "FileType.MP3");
    set_integer(71, module_object, "FileType.MP4");
    set_integer(72, module_object, "FileType.MPEG");
    set_integer(73, module_object, "FileType.MSCOMPRESS");
    set_integer(74, module_object, "FileType.MSI");
    set_integer(75, module_object, "FileType.NE_DLL");
    set_integer(76, module_object, "FileType.NE_EXE");
    set_integer(77, module_object, "FileType.ODF");
    set_integer(78, module_object, "FileType.ODG");
    set_integer(79, module_object, "FileType.ODP");
    set_integer(80, module_object, "FileType.ODS");
    set_integer(81, module_object, "FileType.ODT");
    set_integer(82, module_object, "FileType.OGG");
    set_integer(83, module_object, "FileType.OUTLOOK");
    set_integer(84, module_object, "FileType.PALMOS");
    set_integer(85, module_object, "FileType.PASCAL");
    set_integer(86, module_object, "FileType.PDF");
    set_integer(87, module_object, "FileType.PE_DLL");
    set_integer(88, module_object, "FileType.PE_EXE");
    set_integer(89, module_object, "FileType.PERL");
    set_integer(90, module_object, "FileType.PHP");
    set_integer(91, module_object, "FileType.PKG");
    set_integer(92, module_object, "FileType.PNG");
    set_integer(93, module_object, "FileType.PPSX");
    set_integer(94, module_object, "FileType.PPT");
    set_integer(95, module_object, "FileType.PPTX");
    set_integer(96, module_object, "FileType.PS");
    set_integer(97, module_object, "FileType.PSD");
    set_integer(98, module_object, "FileType.PYTHON");
    set_integer(99, module_object, "FileType.QUICKTIME");
    set_integer(100, module_object, "FileType.RAR");
    set_integer(101, module_object, "FileType.RM");
    set_integer(102, module_object, "FileType.ROM");
    set_integer(103, module_object, "FileType.RPM");
    set_integer(104, module_object, "FileType.RTF");
    set_integer(105, module_object, "FileType.RUBY");
    set_integer(106, module_object, "FileType.RZIP");
    set_integer(107, module_object, "FileType.SCRIPT");
    set_integer(108, module_object, "FileType.SEVENZIP");
    set_integer(109, module_object, "FileType.SHELLSCRIPT");
    set_integer(110, module_object, "FileType.SVG");
    set_integer(111, module_object, "FileType.SWF");
    set_integer(112, module_object, "FileType.SYMBIAN");
    set_integer(113, module_object, "FileType.T3GP");
    set_integer(114, module_object, "FileType.TAR");
    set_integer(115, module_object, "FileType.TARGA");
    set_integer(116, module_object, "FileType.TEXT");
    set_integer(117, module_object, "FileType.TIFF");
    set_integer(118, module_object, "FileType.TORRENT");
    set_integer(119, module_object, "FileType.TTF");
    set_integer(120, module_object, "FileType.WAV");
    set_integer(121, module_object, "FileType.WINCE");
    set_integer(122, module_object, "FileType.WMA");
    set_integer(123, module_object, "FileType.WMV");
    set_integer(124, module_object, "FileType.WOFF");
    set_integer(125, module_object, "FileType.XLS");
    set_integer(126, module_object, "FileType.XLSX");
    set_integer(127, module_object, "FileType.XML");
    set_integer(128, module_object, "FileType.XPI");
    set_integer(129, module_object, "FileType.XWD");
    set_integer(130, module_object, "FileType.ZIP");
    set_integer(131, module_object, "FileType.ZLIB");
}

int module_load(
    YR_SCAN_CONTEXT *context,
    YR_OBJECT *module_object,
    void *module_data,
    size_t module_data_size)
{
    if (module_data_size != 0)
    {
        YR_DEBUG_FPRINTF(1, stderr, "%s", "Parsing JSON\n");
        setup_constants(module_object);
        parse_vt_json(module_object, (char *)module_data, module_data_size);
    }
    else
    {
        YR_DEBUG_FPRINTF(1, stderr, "%s", "Error: No module data specified - pass JSON via '-x vt=/path/to/json'\n");
        return 1;
    }
    return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT *module_object)
{
    return ERROR_SUCCESS;
}
