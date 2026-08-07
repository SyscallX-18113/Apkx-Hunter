/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

#ifndef FUNCTIONS_H
#define FUNCTIONS_H
#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <regex.h>
#include <sys/types.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include "patterns.h"


int statics();
int statics_1();
void scan_buckets(const char *filepath, FILE *for_regex, char *line, int bucket_count, int line_no);
void scan_patterns(const char *filepath, FILE *for_patterns, char *line, int line_no);
void scan_permissions(const char *filepath, FILE *for_permissions, char *line, int line_no);
void scan_exported_activity(const char *filepath, FILE *for_permissions, char *line, int line_no);
void scan_native_libraries(const char *filepath, FILE *for_native_lib);
void print_files(const char *filepath, FILE *scan_files);
void scan_strings_xml(const char *filepath, FILE *for_regex, char *line, int line_no);
void cleanup_bucket_regexes(void);
int init_bucket_regexes(void);
int is_apk(const char *filename);
int check_apk(char *apk_path);
int compute_hashes(const char *filepath);
void install_missing_dependencies(void);


#include "define.h"
#include "main_ai.h"
#include "file_making.h"
#include "scan_dir_func.h"
#include "scan_secrets.h"



#endif