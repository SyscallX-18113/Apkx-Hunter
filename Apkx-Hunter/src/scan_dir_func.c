/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */


#include "scan_dir_func.h"

void scan_dir(const char *path, FILE *for_patterns, FILE *for_regex, FILE *for_permissions, char *shell_argv[], int shell_argc, char *output_dir, FILE *for_weak_network, FILE *for_platform_defense, FILE *for_data_storage, FILE *for_code_execution, FILE *for_web_native)
{

    struct dirent *entry;
    DIR *dp = opendir(path);

    if (!dp)
        return;

    char fullpath[2048];

    while ((entry = readdir(dp)))
    {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(fullpath, sizeof(fullpath),
                 "%s/%s", path, entry->d_name);

        struct stat st;
        stat(fullpath, &st);

        if (S_ISDIR(st.st_mode))
        {
            scan_dir(fullpath, for_patterns, for_regex, for_permissions, shell_argv, shell_argc, output_dir, for_weak_network, for_platform_defense, for_data_storage, for_code_execution, for_web_native); 
        }
        else
        {
            scan_file(fullpath, for_patterns, for_regex, for_permissions, for_weak_network, for_platform_defense, for_data_storage, for_code_execution, for_web_native);
            stats.files_analyzed++;
        }
    }

    closedir(dp);
}


void scan_dir_sec(const char *path, FILE *for_regex, char *shell_argv[], int shell_argc, char *output_dir)
{
    
    struct dirent *entry;
    DIR *dp = opendir(path);

    if (!dp)
        return;

    char fullpath[2048];

    while ((entry = readdir(dp)))
    {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(fullpath, sizeof(fullpath),
                 "%s/%s", path, entry->d_name);

        struct stat st;
        stat(fullpath, &st);

        if (S_ISDIR(st.st_mode))
        {
            scan_dir_sec(fullpath, for_regex, shell_argv, shell_argc, output_dir); 
        }
        else
        {
            scan_file_sec(fullpath, for_regex);
            stats.files_analyzed++;
        }
    }

    closedir(dp);
}

void scan_dir_masvs(const char *path, FILE *for_weak_network, FILE *for_platform_defense, FILE *for_data_storage, FILE *for_code_execution, FILE *for_web_native, char *shell_argv[], int shell_argc, char *output_dir)
{
    
    struct dirent *entry;
    DIR *dp = opendir(path);

    if (!dp)
        return;

    char fullpath[2048];

    while ((entry = readdir(dp)))
    {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(fullpath, sizeof(fullpath),
                 "%s/%s", path, entry->d_name);

        struct stat st;
        stat(fullpath, &st);

        if (S_ISDIR(st.st_mode))
        {
            scan_dir_masvs(fullpath, for_weak_network, for_platform_defense, for_data_storage, for_code_execution, for_web_native, shell_argv, shell_argc, output_dir); 
        }
        else
        {
            scan_file_masvs(fullpath, for_weak_network, for_platform_defense, for_data_storage, for_code_execution, for_web_native);
            stats.files_analyzed++;
        }
    }

    closedir(dp);
}



void scan_dir_per(const char *path, FILE *for_permissions, char *shell_argv[], int shell_argc, char *output_dir)
{
    
    struct dirent *entry;
    DIR *dp = opendir(path);

    if (!dp)
        return;

    char fullpath[2048];

    while ((entry = readdir(dp)))
    {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(fullpath, sizeof(fullpath),
                 "%s/%s", path, entry->d_name);

        struct stat st;
        stat(fullpath, &st);

        if (S_ISDIR(st.st_mode))
        {
            scan_dir_per(fullpath, for_permissions, shell_argv, shell_argc, output_dir); 
        }
        else
        {
            scan_file_per(fullpath, for_permissions);
            stats.files_analyzed++;
        }
    }

    closedir(dp);
}



void scan_dir_pat(const char *path, FILE *for_patterns, char *shell_argv[], int shell_argc, char *output_dir)
{
    
    struct dirent *entry;
    DIR *dp = opendir(path);

    if (!dp)
        return;

    char fullpath[2048];

    while ((entry = readdir(dp)))
    {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(fullpath, sizeof(fullpath),
                 "%s/%s", path, entry->d_name);

        struct stat st;
        stat(fullpath, &st);

        if (S_ISDIR(st.st_mode))
        {
            scan_dir_pat(fullpath, for_patterns, shell_argv, shell_argc, output_dir); 
        }
        else
        {
            scan_file_pat(fullpath, for_patterns);
            stats.files_analyzed++;
        }
    }

    closedir(dp);
}

void scan_dir_files(const char *path, FILE *scan_files, FILE *for_native_lib)
{
    
    struct dirent *entry;
    DIR *dp = opendir(path);

    if (!dp)
        return;

    char fullpath[2048];

    while ((entry = readdir(dp)))
    {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(fullpath, sizeof(fullpath),
                 "%s/%s", path, entry->d_name);

        struct stat st;
        stat(fullpath, &st);

        if (S_ISDIR(st.st_mode))
        {
            scan_dir_files(fullpath, scan_files, for_native_lib); 
        }
        else
        {
            scan_file_files(fullpath, scan_files, for_native_lib);
            stats.files_analyzed++;
        }
    }

    closedir(dp);
}


void scan_dir_for_apktool(FILE *scan_files, const char *path, FILE *for_patterns, FILE *for_regex, FILE *for_permissions, char *shell_argv[], int shell_argc, char *output_dir, FILE *for_weak_network, FILE *for_platform_defense, FILE *for_data_storage, FILE *for_code_execution, FILE *for_web_native)
{

    struct dirent *entry;
    DIR *dp = opendir(path);

    if (!dp)
        return;

    char fullpath[2048];

    while ((entry = readdir(dp)))
    {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(fullpath, sizeof(fullpath),
                 "%s/%s", path, entry->d_name);

        struct stat st;
        stat(fullpath, &st);

        if (S_ISDIR(st.st_mode))
        {
            scan_dir_for_apktool(scan_files, fullpath, for_patterns, for_regex, for_permissions, shell_argv, shell_argc, output_dir, for_weak_network, for_platform_defense, for_data_storage, for_code_execution, for_web_native);
        }
        else
        {
            scan_file_for_apktool(scan_files, fullpath, for_patterns, for_regex, for_permissions, for_weak_network, for_platform_defense, for_data_storage, for_code_execution, for_web_native);
            stats.files_analyzed++;
        }
    }

    closedir(dp);
}



void scan_dir_for_apktool_sec(const char *path, FILE *for_regex, char *shell_argv[], int shell_argc, char *output_dir)
{
    
    struct dirent *entry;
    DIR *dp = opendir(path);

    if (!dp)
        return;

    char fullpath[2048];

    while ((entry = readdir(dp)))
    {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(fullpath, sizeof(fullpath),
                 "%s/%s", path, entry->d_name);

        struct stat st;
        stat(fullpath, &st);

        if (S_ISDIR(st.st_mode))
        {
            scan_dir_for_apktool_sec(fullpath, for_regex, shell_argv, shell_argc, output_dir); 
        }
        else
        {
            scan_file_for_apktool_sec(fullpath, for_regex);
            stats.files_analyzed++;
        }
    }

    closedir(dp);
}

void scan_dir_for_apktool_masvs(const char *path, FILE *for_weak_network, FILE *for_platform_defense, FILE *for_data_storage, FILE *for_code_execution, FILE *for_web_native, char *shell_argv[], int shell_argc, char *output_dir)
{
    
    struct dirent *entry;
    DIR *dp = opendir(path);

    if (!dp)
        return;

    char fullpath[2048];

    while ((entry = readdir(dp)))
    {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(fullpath, sizeof(fullpath),
                 "%s/%s", path, entry->d_name);

        struct stat st;
        stat(fullpath, &st);

        if (S_ISDIR(st.st_mode))
        {
            scan_dir_for_apktool_masvs(fullpath, for_weak_network, for_platform_defense, for_data_storage, for_code_execution, for_web_native, shell_argv, shell_argc, output_dir); 
        }
        else
        {
            scan_file_for_apktool_masvs(fullpath, for_weak_network, for_platform_defense, for_data_storage, for_code_execution, for_web_native);
            stats.files_analyzed++;
        }
    }

    closedir(dp);
}




void scan_dir_for_apktool_per(const char *path, FILE *for_permissions, char *shell_argv[], int shell_argc, char *output_dir)
{
    
    struct dirent *entry;
    DIR *dp = opendir(path);

    if (!dp)
        return;

    char fullpath[2048];

    while ((entry = readdir(dp)))
    {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(fullpath, sizeof(fullpath),
                 "%s/%s", path, entry->d_name);

        struct stat st;
        stat(fullpath, &st);

        if (S_ISDIR(st.st_mode))
        {
            scan_dir_for_apktool_per(fullpath, for_permissions, shell_argv, shell_argc, output_dir);
            
        }
        else
        {
            scan_file_for_apktool_per(fullpath, for_permissions);
            stats.files_analyzed++;
        }
    }

    closedir(dp);
}



void scan_dir_for_apktool_pat(const char *path, FILE *for_patterns, char *shell_argv[], int shell_argc, char *output_dir)
{
    
    struct dirent *entry;
    DIR *dp = opendir(path);

    if (!dp)
        return;

    char fullpath[2048];

    while ((entry = readdir(dp)))
    {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(fullpath, sizeof(fullpath),
                 "%s/%s", path, entry->d_name);

        struct stat st;
        stat(fullpath, &st);

        if (S_ISDIR(st.st_mode))
        {
            scan_dir_for_apktool_pat(fullpath, for_patterns, shell_argv, shell_argc, output_dir);
        }
        else
        {
            scan_file_for_apktool_pat(fullpath, for_patterns);
            stats.files_analyzed++;
        }
    }

    closedir(dp);
}

void scan_dir_for_apktool_files(const char *path, FILE *scan_files, FILE *for_native_lib)
{
    
    struct dirent *entry;
    DIR *dp = opendir(path);

    if (!dp)
        return;

    char fullpath[2048];

    while ((entry = readdir(dp)))
    {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(fullpath, sizeof(fullpath),
                 "%s/%s", path, entry->d_name);

        struct stat st;
        stat(fullpath, &st);

        if (S_ISDIR(st.st_mode))
        {
            scan_dir_for_apktool_files(fullpath, scan_files, for_native_lib);
            
        }
        else
        {
            scan_file_for_apktool_files(fullpath, scan_files, for_native_lib);
            stats.files_analyzed++;
        }
    }

    closedir(dp);
}
