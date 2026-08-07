/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

#include "multi_apk.h"


void scan_multi_apk(const char *directory, int argc, char *argv[])
{
    DIR *dir;
    struct dirent *entry;
    struct stat st;
    char full_path[8192];
    char output_dir[256];
    char output_dir_1[256];

    dir = opendir(directory);

    if (dir == NULL)
    {
        perror(directory);
        return;
    }

    while ((entry = readdir(dir)) != NULL)
    {

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }

        snprintf(full_path,
                 sizeof(full_path),
                 "%s/%s",
                 directory,
                 entry->d_name);

        const char *apk_name = strrchr(full_path, '/');

        if (apk_name)
            apk_name++;
        else
            apk_name = full_path;

        char *dot = strstr(apk_name, ".apk");

        if (dot)
        {
            ptrdiff_t len = dot - apk_name;

            snprintf(output_dir,
                     sizeof(output_dir),
                     "Jadx_output_%.*s",
                     (int)len,
                     apk_name);
        }
        else
        {
            snprintf(output_dir,
                     sizeof(output_dir),
                     "output_default");
        }

        
        const char *apk_name_1 = strrchr(full_path, '/');

        if (apk_name_1)
            apk_name_1++;
        else
            apk_name_1 = full_path;

        char *dot_1 = strstr(apk_name_1, ".apk");

        if (dot_1)
        {
            ptrdiff_t len_1 = dot_1 - apk_name_1;

            snprintf(output_dir_1,
                     sizeof(output_dir_1),
                     "Apktool_output_%.*s",
                     (int)len_1,
                     apk_name_1);
        }
        else
        {
            snprintf(output_dir_1,
                     sizeof(output_dir_1),
                     "output_default");
        }

        if (stat(full_path, &st) != 0)
        {
            continue;
        }

       
        if (S_ISDIR(st.st_mode))
        {
            scan_multi_apk(full_path, argc, argv);
        }

       
        else if (S_ISREG(st.st_mode))
        {
            const char *ext = strrchr(entry->d_name, '.');

            if (ext != NULL && strcmp(ext, ".apk") == 0)
            {
                if (apktool_2 == 1)
                {
                    run_apktool_1(argv, full_path, output_dir_1, argc);
                    
                    
                }
                else
                {
                    run_jadx_1(argv, full_path, output_dir, argc);
                
                    
                }
            }
        }
    }
    statics_1();

    closedir(dir);
}
