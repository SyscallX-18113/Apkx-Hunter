/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

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

int scan_file(const char *filepath, FILE *for_patterns, FILE *for_regex, FILE *for_permissions, FILE *for_masvs);
int scan_file_sec(const char *filepath, FILE *for_regex);
int scan_file_per(const char *filepath, FILE *for_permissions);
int scan_file_pat(const char *filepath, FILE *for_patterns);
int scan_file_files(const char *filepath, FILE *scan_files, FILE *for_native_lib);
int scan_file_for_apktool(FILE *scan_files, const char *filepath, FILE *for_patterns, FILE *for_regex, FILE *for_permissions, FILE *for_masvs);
int scan_file_for_apktool_sec(const char *filepath, FILE *for_regex);
int scan_file_for_apktool_per(const char *filepath, FILE *for_permissions);
int scan_file_for_apktool_pat(const char *filepath, FILE *for_patterns);
int scan_file_for_apktool_files(const char *filepath, FILE *scan_files, FILE *for_native_lib);
int scan_file_masvs(const char *filepath, FILE *for_masvs);
int scan_file_for_apktool_masvs(const char *filepath, FILE *for_masvs);

#include "patterns.h"
#include "define.h"
#include "main_ai.h"
#include "file_making.h"
#include "scan_dir_func.h"
#include "scan_secrets.h"
#include "masvs.h"



#endif