
/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */


#ifndef AH_SHELL_INTERFACE
#define AH_SHELL_INTERFACE

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <regex.h>
#include <sys/types.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <stddef.h>
#include "define.h"
#include "banner.h"
#include "patterns.h"
#include "functions.h"
#include "jadx.h"
#include "scan_secrets.h"
#include "apktool.h"
#include "extract.h"
#include "multi_apk.h"
#include "masvs.h"
#include "ah_shell_interface.h"

#define MAX_SHELL_ARGS 64
#define MAX_COMMAND_LEN 1024



int run_command(int shell_argc, char *shell_argv[]);
int parse_shell_args(char *command, char **shell_argv);
int command_line();

#endif
