#include "json_utils.h"
#include <yara/globals.h>

#include <string.h>

cJSON *json_get_obj(cJSON *json,const char *name)
{
    if(!cJSON_IsObject(json))
    {
        YR_DEBUG_FPRINTF(1,stderr,"Called json_get_obj on non-object (or nullptr)\n");
        return NULL;
    }
    for(cJSON *p = json->child; p != NULL; p = p->next)
    {
        if(!p)
            return NULL;
        if(!strcmp(p->string,name))
            return p;
    }
    YR_DEBUG_FPRINTF(1,stderr,"json_get_obj failed to find %s\n",name);
    return NULL;
}

int json_get_int(cJSON *json)
{
    if(!cJSON_IsNumber(json))
    {
        YR_DEBUG_FPRINTF(1,stderr,"Called json_get_int on non-number object (or nullptr)\n");
        return 0;
    }
    return json->valueint;
}

double json_get_double(cJSON *json)
{
    if(!cJSON_IsNumber(json))
    {
        YR_DEBUG_FPRINTF(1,stderr,"Called json_get_double on non-number object (or nullptr)\n");
        return 0;
    }
    return json->valuedouble; 
}

int json_obj_get_int(cJSON *json,const char *name)
{
    cJSON *val = json_get_obj(json,name);
    if(!val)
        return 0;
    return json_get_int(val);
}

//convenience for cleaner API use
static const char json_empty_str[] = "";

const char *json_get_string(cJSON *json)
{
    if(!cJSON_IsString(json))
    {
        YR_DEBUG_FPRINTF(1,stderr,"Called json_get_string on non-string object (or nullptr)\n");
        return json_empty_str;
    }
    return json->valuestring;
}

const char *json_obj_get_string(cJSON *json,const char *name)
{
    cJSON *val = json_get_obj(json,name);
    if(!val)
        return json_empty_str;
    return json_get_string(val);
}