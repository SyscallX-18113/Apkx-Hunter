/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

#ifndef MULTI_APK_H
#define MULTI_APK_H

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
#include "define.h"
#include "jadx.h"
#include "apktool.h"

void scan_multi_apk(const char *directory, int argc, char *argv[]);


#endif