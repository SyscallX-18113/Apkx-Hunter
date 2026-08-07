/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

#ifndef JADX_H
#define JADX_H

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include "define.h"
#include "file_making.h"
#include "functions.h"

int directory_exists(const char *path);
int run_jadx(char *argv[], char *output_dir, int argc);
int run_jadx_1(char *argv[], char *full_path, char *output_dir, int argc);

#endif