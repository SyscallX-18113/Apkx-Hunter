#ifndef SCAN_FILE_FUNC_H
#define SCAN_FILE_FUNC_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <regex.h>
#include <sys/types.h>

int scan_file(const char *filepath, FILE *for_patterns, FILE *for_regex, FILE *for_permissions);
int scan_file_sec(const char *filepath, FILE *for_regex);
int scan_file_per(const char *filepath, FILE *for_permissions);
int scan_file_pat(const char *filepath, FILE *for_patterns);
int scan_file_files(const char *filepath, FILE *scan_files, FILE *for_native_lib);
int scan_file_for_apktool(FILE *scan_files, const char *filepath, FILE *for_patterns, FILE *for_regex, FILE *for_permissions);
int scan_file_for_apktool_sec(const char *filepath, FILE *for_regex);
int scan_file_for_apktool_per(const char *filepath, FILE *for_permissions);
int scan_file_for_apktool_pat(const char *filepath, FILE *for_patterns);
int scan_file_for_apktool_files(const char *filepath, FILE *scan_files, FILE *for_native_lib);

#include "patterns.h"
#include "define.h"
#include "main_ai.h"
#include "file_making.h"
#include "scan_dir_func.h"
#include "scan_secrets.h"

int scan_file(const char *filepath, FILE *for_patterns, FILE *for_regex, FILE *for_permissions)
{

    FILE *f = fopen(filepath, "r");
    if (!f)
    {  
    return 1;
    }

    char line[MAX_LINE];
    int line_no = 0;

    int bucket_count =
        sizeof(Bucket) / sizeof(Bucket[0]);

    int count_secrets = sizeof(secrets) / sizeof(secrets[0]);

    while (fgets(line, sizeof(line), f))
    {
        line_no++;
        scan_patterns(filepath, for_patterns, line, line_no);
        scan_buckets(filepath, for_regex, line, bucket_count, line_no);
        scan_secrets(filepath, for_regex, line, count_secrets, line_no);
        scan_permissions(filepath, for_permissions, line, line_no);
        scan_exported_activity(filepath, for_permissions, line, line_no);
        scan_strings_xml(filepath, for_regex, line, line_no);
        
    }

    fclose(f);
}

int scan_file_sec(const char *filepath, FILE *for_regex)
{

    FILE *f = fopen(filepath, "r");
    if (!f)
    {  
    return 1;
    }

    char line[MAX_LINE];
    int line_no = 0;

    int bucket_count = sizeof(Bucket) / sizeof(Bucket[0]);

    int count_secrets = sizeof(secrets) / sizeof(secrets[0]);

    while (fgets(line, sizeof(line), f))
    {
        line_no++;
        scan_buckets(filepath, for_regex, line, bucket_count, line_no);
        scan_secrets(filepath, for_regex, line, count_secrets, line_no);
        scan_strings_xml(filepath, for_regex, line, line_no);
        
    }

    fclose(f);
}

int scan_file_per(const char *filepath, FILE *for_permissions)
{

    FILE *f = fopen(filepath, "r");
    if (!f)
    {  
    return 1;
    }

    char line[MAX_LINE];
    int line_no = 0;

    

    

    while (fgets(line, sizeof(line), f))
    {
        line_no++;
        scan_permissions(filepath, for_permissions, line, line_no);
        scan_exported_activity(filepath, for_permissions, line, line_no);
    }

    fclose(f);
}

int scan_file_pat(const char *filepath, FILE *for_patterns)
{

    FILE *f = fopen(filepath, "r");
    if (!f)
    {  
    return 1;
    }

    char line[MAX_LINE];
    int line_no = 0;

    
    while (fgets(line, sizeof(line), f))
    {
        line_no++;
        scan_patterns(filepath, for_patterns, line, line_no);
    }

    fclose(f);
}

int scan_file_files(const char *filepath, FILE *scan_files, FILE *for_native_lib)
{

    FILE *f = fopen(filepath, "r");
    if (!f)
    {  
    return 1;
    }


    print_files(filepath, scan_files);
    scan_native_libraries(filepath, for_native_lib);

    fclose(f);
}



int scan_file_for_apktool(FILE *scan_files, const char *filepath, FILE *for_patterns, FILE *for_regex, FILE *for_permissions)
{

    FILE *f = fopen(filepath, "r");
    if (!f)
    {  
    return 1;
    }

    char line[MAX_LINE];
    int line_no = 0;

    int bucket_count =
        sizeof(Bucket) / sizeof(Bucket[0]);

    int count_secrets = sizeof(secrets) / sizeof(secrets[0]);

    if (strstr(filepath, ".xml") != NULL || strstr(filepath, ".json") != NULL || strstr(filepath, ".properties") != NULL || strstr(filepath, ".txt") != NULL || strstr(filepath, ".conf") != NULL || strstr(filepath, ".ini") != NULL || strstr(filepath, ".yaml") != NULL || strstr(filepath, ".yml") != NULL || strstr(filepath, ".env") != NULL || strstr(filepath, ".db") != NULL || strstr(filepath, ".sqlite") != NULL || strstr(filepath, ".pem") != NULL || strstr(filepath, ".cer") != NULL || strstr(filepath, ".crt") != NULL || strstr(filepath, ".key") != NULL || strstr(filepath, ".p12") != NULL || strstr(filepath, ".jks") != NULL || strstr(filepath, ".keystore") != NULL)
    {
        while (fgets(line, sizeof(line), f))
        {
            line_no++;
            scan_patterns(filepath, for_patterns, line, line_no);
            scan_buckets(filepath, for_regex, line, bucket_count, line_no);
            scan_secrets(filepath, for_regex, line, count_secrets, line_no);
            scan_permissions(filepath, for_permissions, line, line_no);
            scan_exported_activity(filepath, for_permissions, line, line_no);
            scan_strings_xml(filepath, for_regex, line, line_no);
        }
        print_files(filepath, scan_files);
    }

    fclose(f);
}


int scan_file_for_apktool_sec(const char *filepath, FILE *for_regex)
{

    FILE *f = fopen(filepath, "r");
    if (!f)
    {  
    return 1;
    }

    char line[MAX_LINE];
    int line_no = 0;

    int bucket_count =
        sizeof(Bucket) / sizeof(Bucket[0]);

    int count_secrets = sizeof(secrets) / sizeof(secrets[0]);

    if (strstr(filepath, ".xml") != NULL || strstr(filepath, ".json") != NULL || strstr(filepath, ".properties") != NULL || strstr(filepath, ".txt") != NULL || strstr(filepath, ".conf") != NULL || strstr(filepath, ".ini") != NULL || strstr(filepath, ".yaml") != NULL || strstr(filepath, ".yml") != NULL || strstr(filepath, ".env") != NULL || strstr(filepath, ".db") != NULL || strstr(filepath, ".sqlite") != NULL || strstr(filepath, ".pem") != NULL || strstr(filepath, ".cer") != NULL || strstr(filepath, ".crt") != NULL || strstr(filepath, ".key") != NULL || strstr(filepath, ".p12") != NULL || strstr(filepath, ".jks") != NULL || strstr(filepath, ".keystore") != NULL)
    {
        while (fgets(line, sizeof(line), f))
        {
            line_no++;
            
            scan_buckets(filepath, for_regex, line, bucket_count, line_no);
            scan_secrets(filepath, for_regex, line, count_secrets, line_no);
            scan_strings_xml(filepath, for_regex, line, line_no);
        }
        
    }

    fclose(f);
}

int scan_file_for_apktool_per(const char *filepath, FILE *for_permissions)
{

    FILE *f = fopen(filepath, "r");
    if (!f)
    {  
    return 1;
    }
    char line[MAX_LINE];
    int line_no = 0;

    if (strstr(filepath, ".xml") != NULL || strstr(filepath, ".json") != NULL || strstr(filepath, ".properties") != NULL || strstr(filepath, ".txt") != NULL || strstr(filepath, ".conf") != NULL || strstr(filepath, ".ini") != NULL || strstr(filepath, ".yaml") != NULL || strstr(filepath, ".yml") != NULL || strstr(filepath, ".env") != NULL || strstr(filepath, ".db") != NULL || strstr(filepath, ".sqlite") != NULL || strstr(filepath, ".pem") != NULL || strstr(filepath, ".cer") != NULL || strstr(filepath, ".crt") != NULL || strstr(filepath, ".key") != NULL || strstr(filepath, ".p12") != NULL || strstr(filepath, ".jks") != NULL || strstr(filepath, ".keystore") != NULL)
    {
        while (fgets(line, sizeof(line), f))
        {
            line_no++;
            scan_permissions(filepath, for_permissions, line, line_no);
            scan_exported_activity(filepath, for_permissions, line, line_no);
        }
        
    }

    fclose(f);
}

int scan_file_for_apktool_pat(const char *filepath, FILE *for_patterns)
{

    FILE *f = fopen(filepath, "r");
    if (!f)
    {  
    return 1;
    }

    char line[MAX_LINE];
    int line_no = 0;


    if (strstr(filepath, ".xml") != NULL || strstr(filepath, ".json") != NULL || strstr(filepath, ".properties") != NULL || strstr(filepath, ".txt") != NULL || strstr(filepath, ".conf") != NULL || strstr(filepath, ".ini") != NULL || strstr(filepath, ".yaml") != NULL || strstr(filepath, ".yml") != NULL || strstr(filepath, ".env") != NULL || strstr(filepath, ".db") != NULL || strstr(filepath, ".sqlite") != NULL || strstr(filepath, ".pem") != NULL || strstr(filepath, ".cer") != NULL || strstr(filepath, ".crt") != NULL || strstr(filepath, ".key") != NULL || strstr(filepath, ".p12") != NULL || strstr(filepath, ".jks") != NULL || strstr(filepath, ".keystore") != NULL)
    {
        while (fgets(line, sizeof(line), f))
        {
            line_no++;
            scan_patterns(filepath, for_patterns, line, line_no);
        }
        
    }

    fclose(f);
}

int scan_file_for_apktool_files(const char *filepath, FILE *scan_files, FILE *for_native_lib)
{

    FILE *f = fopen(filepath, "r");
    if (!f)
    {
        return 1;
    }

    print_files(filepath, scan_files);
    scan_native_libraries(filepath, for_native_lib);

    fclose(f);
}

#endif