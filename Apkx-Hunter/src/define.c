/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

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
#include "define.h"


int silent_mode = 1;
int deep_2 = 0;
int fast_2 = 0;
int secrets_2 = 0;
int help_2 = 0;
int folder_scan_2 = 0;
int permissions_2 = 0;
int patterns_2 = 0;
int decompile_2 = 0;
int file_scan_2 = 0;
int apktool_2 = 0;
int apktool_scan_2 = 0;
int multi_apk_2 = 0;
int extract_2 = 0;
int masvs_2 = 0;
int extract_multi_apk_2 = 0;
int install = 0;

int not_valid_apk = 0;
int apk_count = 0;


const char *valid_flags[] =
{
    INSTALL,
    FAST,
    DEEP,
    EXTRACT_MULTI_APK,
    FOLDER_SCAN,
    APKTOOL,
    MULTI_APK,
    DECOMPILE,
    APKTOOL_SCAN,
    EXTRACT,
    SECRETS,
    MASVS,
    PERMISSIONS,
    PATTERNS,
    FILE_SCAN,
    HELP
};

ScanStats stats = {0};

int valid_flag_count = sizeof(valid_flags) / sizeof(valid_flags[0]);
