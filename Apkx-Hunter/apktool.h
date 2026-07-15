#ifndef APKTOOL_H
#define APKTOOL_H

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "define.h"
#include "file_making.h"
#include "functions.h"



int run_apktool(char *argv[], char *output_dir, int argc)
{
    
    char cmd[8192];
    char full_path[2048];
    char cwd[1024];
    getcwd(cwd, sizeof(cwd));
    char Half_path[2048];

    snprintf(full_path, sizeof(full_path), "%s/%s", cwd, argv[1]);
    snprintf(Half_path, sizeof(Half_path), "%s", cwd);

    check_apk(full_path);
    compute_hashes(full_path);
   

    if (argc == 3)
    {
        
        

        snprintf(cmd, sizeof(cmd), "apktool -f d %s -o %s/%s", full_path, Half_path, output_dir);
        

        system(cmd);
        
    }

    else if (argc == 4 && (strcmp(argv[3], SECRETS) == 0 || strcmp(argv[3], PERMISSIONS) == 0 || strcmp(argv[3], PATTERNS) == 0 || strcmp(argv[3], EXTRACT) == 0 || strcmp(argv[3], FILE_SCAN) == 0))
    {
        
        
        snprintf(cmd, sizeof(cmd), "apktool -f d %s -o %s/%s", full_path, Half_path, output_dir);

        system(cmd);
        
        
    }


    else if (argc == 4 && strcmp(argv[3], DECOMPILE) == 0)
    {
        
        snprintf(cmd, sizeof(cmd), "apktool -f d %s -o %s/%s", full_path, Half_path, output_dir);

        system(cmd);
        printf(HACKER_WHITE "\nDecompilation successful\n" COLOR_RESET);
        return 0;

    }

 
    file_making_for_apktool(output_dir, argv, argc);
    return 0;
}


#endif
