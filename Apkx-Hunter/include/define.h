/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

#ifndef DEFINE_H
#define DEFINE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <regex.h>
#include <sys/types.h>
#include <stddef.h>
#include "patterns.h"


//COLORS
#define COLOR_MAGENTA         "\033[1;35m"
#define COLOR_RESET           "\033[0m"
#define GREEN                 "\033[32m"
#define COLOR_RED             "\033[1;31m"
#define COLOR_BLUE            "\033[1;34m"
#define _G                    "\033[38;5;46m"
#define LIGHT_BLUE            "\033[96m"
#define LIGHT_GREEN           "\033[92m"
#define LIGHT_BLUE_SECOND     "\033[94m"
#define LIGHT_MAGENTA         "\033[95m"
#define LIGHT_CYAN            "\033[96m"
#define LIGHT_WHITE           "\033[97m"
#define LIGHT_YELLOW          "\033[93m"

#define LIGHT_RED             "\033[91m"
#define ORANGE                "\033[38;2;255;165;0m"
#define HACKER_WHITE          "\033[97m"

 

//Other Defines

#define MAX_LINE 2048


//Flags

#define DEEP "--deep"
#define FAST "--fast"
#define SECRETS "--secrets"
#define HELP "--help"
#define FOLDER_SCAN "--folder-scan"
#define PERMISSIONS "--permissions"
#define PATTERNS "--endpoints"
#define DECOMPILE "--decompile"
#define FILE_SCAN "--files"
#define APKTOOL "--apktool"
#define APKTOOL_SCAN "--apktool-folder-scan"
#define MULTI_APK "--multi-apk"
#define EXTRACT "--extract"
#define MASVS "--masvs"
#define EXTRACT_MULTI_APK "--extract-multi-apk"
#define INSTALL "--install-dependencies"


extern int silent_mode;
extern int deep_2;
extern int fast_2;
extern int secrets_2;
extern int help_2;
extern int folder_scan_2;
extern int permissions_2;
extern int patterns_2;
extern int decompile_2;
extern int file_scan_2;
extern int apktool_2;
extern int apktool_scan_2;
extern int multi_apk_2;
extern int extract_2;
extern int masvs_2;
extern int extract_multi_apk_2;
extern int install;

extern int not_valid_apk;
extern int apk_count;
extern int valid_flag_count;

extern const char *valid_flags[];

typedef struct
{
    int apks_scanned;
    int duplicate_apks_skipped;
    int files_analyzed;
    int secrets;
    int patterns;
    int masvs;
    int permissions;
} ScanStats;

extern ScanStats stats;

#endif