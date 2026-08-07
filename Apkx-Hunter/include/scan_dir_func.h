/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

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

void scan_dir(const char *path, FILE *for_patterns, FILE *for_regex, FILE *for_permissions, char *argv[], int argc, char *output_dir, FILE *for_masvs);
void scan_dir_sec(const char *path, FILE *for_regex, char *argv[], int argc, char *output_dir);
void scan_dir_per(const char *path, FILE *for_permissions, char *argv[], int argc, char *output_dir);
void scan_dir_pat(const char *path, FILE *for_patterns, char *argv[], int argc, char *output_dir);
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
#include "masvs.h"



#endif