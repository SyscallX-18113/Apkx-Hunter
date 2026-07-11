#ifndef SCAN_SECRETS_H
#define SCAN_SECRETS_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <regex.h>

int scan_secrets(const char *filepath,
                 FILE *for_regex,
                 char *line,
                 int count_secrets,
                 int line_no);


#include "patterns.h"
#include "define.h"
#include "main_ai.h"
#include "file_making.h"
#include "scan_dir_func.h"


int scan_secrets(const char *filepath,
                 FILE *for_regex,
                 char *line,
                 int count_secrets,
                 int line_no)
{

    printf(LIGHT_RED);
    for (int n = 0; n < count_secrets; n++)
    {
        

        regmatch_t match[3];

        if (regexec(&secret_regexes[n],
                    line,
                    3,
                    match,
                    0) == 0)
        {
            char found[512];

            regoff_t len = match[0].rm_eo - match[0].rm_so;

            if (len >= (regoff_t)sizeof(found))
            {
                len = (regoff_t)sizeof(found) - 1;
            }

            strncpy(
                found,
                line + match[0].rm_so,
                (size_t)len);

            found[len] = '\0';

            const char *dot = strrchr(filepath, '.');

            if (dot && strcmp(dot, ".split3") == 0)
            {
                return 1;
            }

            

            

            ai_model(filepath, for_regex, line_no, found, n);
        }

        
    }
    printf(COLOR_RESET);

    return 0;
}


#endif 