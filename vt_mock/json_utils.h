#pragma once

#include "cJSON.h"

cJSON *json_get_obj(cJSON *json,const char *name);

int json_get_int(cJSON *json);
int json_obj_get_int(cJSON *json,const char *name);

double json_get_double(cJSON *json);
double json_obj_get_double(cJSON *json,const char *name);

const char *json_get_string(cJSON *json);
const char *json_obj_get_string(cJSON *json,const char *name);
