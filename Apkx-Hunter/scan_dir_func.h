#ifndef SCAN_DIR_FUNC_H
#define SCAN_DIR_FUNC_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <regex.h>
#include <sys/types.h>

void scan_dir(const char *path,
              FILE *for_patterns,
              FILE *for_regex,
              FILE *for_permissions,
              char *argv[],
              int argc,
              char *output_dir, FILE *for_masvs);

void scan_dir_sec(const char *path,
                  FILE *for_regex,
                  char *argv[],
                  int argc,
                  char *output_dir);

void scan_dir_per(const char *path,
                  FILE *for_permissions,
                  char *argv[],
                  int argc,
                  char *output_dir);

void scan_dir_pat(const char *path,
                  FILE *for_patterns,
                  char *argv[],
                  int argc,
                  char *output_dir);

void scan_dir_files(const char *path, FILE *scan_files, FILE *for_native_lib);
void scan_dir_for_apktool(FILE *scan_files, const char *path, FILE *for_patterns, FILE *for_regex, FILE *for_permissions, char *argv[], int argc, char *output_dir, FILE *for_masvs);
void scan_dir_for_apktool_sec(const char *path, FILE *for_regex, char *argv[], int argc, char *output_dir);
void scan_dir_for_apktool_per(const char *path, FILE *for_permissions, char *argv[], int argc, char *output_dir);
void scan_dir_for_apktool_pat(const char *path, FILE *for_patterns, char *argv[], int argc, char *output_dir);
void scan_dir_for_apktool_files(const char *path, FILE *scan_files, FILE *for_native_lib);
void scan_dir_masvs(const char *path, FILE *for_masvs, char *argv[], int argc, char *output_dir);
void scan_dir_for_apktool_masvs(const char *path, FILE *for_masvs, char *argv[], int argc, char *output_dir);


#include "patterns.h"
#include "define.h"
#include "main_ai.h"
#include "functions.h"
#include "file_making.h"
#include "scan_file_func.h"


void scan_dir(const char *path, FILE *for_patterns, FILE *for_regex, FILE *for_permissions, char *argv[], int argc, char *output_dir, FILE *for_masvs)
{

    struct dirent *entry;
    DIR *dp = opendir(path);

    if (!dp)
        return;

    char fullpath[1024];

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
            scan_dir(fullpath, for_patterns, for_regex, for_permissions, argv, argc, output_dir, for_masvs); // recursion
        }
        else
        {
            scan_file(fullpath, for_patterns, for_regex, for_permissions, for_masvs);
        }
    }

    closedir(dp);
}


void scan_dir_sec(const char *path, FILE *for_regex, char *argv[], int argc, char *output_dir)
{
    
    struct dirent *entry;
    DIR *dp = opendir(path);

    if (!dp)
        return;

    char fullpath[1024];

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
            scan_dir_sec(fullpath, for_regex, argv, argc, output_dir); // recursion
        }
        else
        {
            scan_file_sec(fullpath, for_regex);
        }
    }

    closedir(dp);
}

void scan_dir_masvs(const char *path, FILE *for_masvs, char *argv[], int argc, char *output_dir)
{
    
    struct dirent *entry;
    DIR *dp = opendir(path);

    if (!dp)
        return;

    char fullpath[1024];

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
            scan_dir_masvs(fullpath, for_masvs, argv, argc, output_dir); // recursion
        }
        else
        {
            scan_file_masvs(fullpath, for_masvs);
        }
    }

    closedir(dp);
}



void scan_dir_per(const char *path, FILE *for_permissions, char *argv[], int argc, char *output_dir)
{
    
    struct dirent *entry;
    DIR *dp = opendir(path);

    if (!dp)
        return;

    char fullpath[1024];

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
            scan_dir_per(fullpath, for_permissions, argv, argc, output_dir); // recursion
        }
        else
        {
            scan_file_per(fullpath, for_permissions);
        }
    }

    closedir(dp);
}



void scan_dir_pat(const char *path, FILE *for_patterns, char *argv[], int argc, char *output_dir)
{
    
    struct dirent *entry;
    DIR *dp = opendir(path);

    if (!dp)
        return;

    char fullpath[1024];

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
            scan_dir_pat(fullpath, for_patterns, argv, argc, output_dir); // recursion
        }
        else
        {
            scan_file_pat(fullpath, for_patterns);
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

    char fullpath[1024];

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
            scan_dir_files(fullpath, scan_files, for_native_lib); // recursion
        }
        else
        {
            scan_file_files(fullpath, scan_files, for_native_lib);
        }
    }

    closedir(dp);
}


void scan_dir_for_apktool(FILE *scan_files, const char *path, FILE *for_patterns, FILE *for_regex, FILE *for_permissions, char *argv[], int argc, char *output_dir, FILE *for_masvs)
{

    struct dirent *entry;
    DIR *dp = opendir(path);

    if (!dp)
        return;

    char fullpath[1024];

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
            scan_dir_for_apktool(scan_files, fullpath, for_patterns, for_regex, for_permissions, argv, argc, output_dir, for_masvs); // recursion
        }
        else
        {
            scan_file_for_apktool(scan_files, fullpath, for_patterns, for_regex, for_permissions, for_masvs);
        }
    }

    closedir(dp);
}

////////

void scan_dir_for_apktool_sec(const char *path, FILE *for_regex, char *argv[], int argc, char *output_dir)
{
    
    struct dirent *entry;
    DIR *dp = opendir(path);

    if (!dp)
        return;

    char fullpath[1024];

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
            scan_dir_for_apktool_sec(fullpath, for_regex, argv, argc, output_dir); // recursion
        }
        else
        {
            scan_file_for_apktool_sec(fullpath, for_regex);
        }
    }

    closedir(dp);
}

void scan_dir_for_apktool_masvs(const char *path, FILE *for_masvs, char *argv[], int argc, char *output_dir)
{
    
    struct dirent *entry;
    DIR *dp = opendir(path);

    if (!dp)
        return;

    char fullpath[1024];

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
            scan_dir_for_apktool_masvs(fullpath, for_masvs, argv, argc, output_dir); // recursion
        }
        else
        {
            scan_file_for_apktool_masvs(fullpath, for_masvs);
        }
    }

    closedir(dp);
}




void scan_dir_for_apktool_per(const char *path, FILE *for_permissions, char *argv[], int argc, char *output_dir)
{
    
    struct dirent *entry;
    DIR *dp = opendir(path);

    if (!dp)
        return;

    char fullpath[1024];

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
            scan_dir_for_apktool_per(fullpath, for_permissions, argv, argc, output_dir); // recursion
        }
        else
        {
            scan_file_for_apktool_per(fullpath, for_permissions);
        }
    }

    closedir(dp);
}



void scan_dir_for_apktool_pat(const char *path, FILE *for_patterns, char *argv[], int argc, char *output_dir)
{
    
    struct dirent *entry;
    DIR *dp = opendir(path);

    if (!dp)
        return;

    char fullpath[1024];

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
            scan_dir_for_apktool_pat(fullpath, for_patterns, argv, argc, output_dir); // recursion
        }
        else
        {
            scan_file_for_apktool_pat(fullpath, for_patterns);
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

    char fullpath[1024];

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
            scan_dir_for_apktool_files(fullpath, scan_files, for_native_lib); // recursion
        }
        else
        {
            scan_file_for_apktool_files(fullpath, scan_files, for_native_lib);
        }
    }

    closedir(dp);
}






#endif
