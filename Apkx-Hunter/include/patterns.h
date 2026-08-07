


#ifndef PATTERNS_H
#define PATTERNS_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex.h>
#include "define.h"

extern const char *patterns[];

typedef struct
{
    const char *name;
    const char *pattern;
} Full_manifest_scan;

typedef struct
{
    const char *name;
    const char *pattern;
} StringPattern;

typedef struct
{
    const char *name;
    const char *pattern;
} RegexBucketsPattern;

typedef struct
{
    const char *name;
    const char *pattern;
    const char *severity;
} RegexSecretPattern;

typedef struct permission
{

    const char *permission;
    const char *definition;

} permission_data;

typedef struct
{
    const char *name;
    const char *pattern;
    const char *severity;
    const char *description;
} masvs_pattern;

extern char *false_positives[];
extern Full_manifest_scan manifest_scan[];
extern StringPattern string_patterns[];
extern RegexBucketsPattern Bucket[];
extern RegexSecretPattern secrets[];
extern permission_data permission[];
extern masvs_pattern masvs_patterns[];
extern masvs_pattern network_security_patterns[];

extern int pattern_count;
extern int permission_count;
extern int manifest_count;
extern int strings_count;

extern int masvs_count;
extern int masvs_network_security_patterns_count;
extern int false_positives_count;
extern int count_patterns;
extern int count_secrets;


extern regex_t bucket_regexes[];
extern regex_t secret_regexes[];



#endif