/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

#include "masvs.h"

void scan_masvs_1(const char *filepath, FILE *for_weak_network, FILE *for_platform_defense, FILE *for_data_storage, FILE *for_code_execution, FILE *for_web_native, char *line, int line_no)
{
    int is_false_positive = 0;

    for (int i = 0; i < weak_network; i++)
    {
        if (strstr(line, weak_networks[i].pattern))
        {

            fprintf(for_weak_network,
                    "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n", weak_networks[i].name, filepath, line_no, weak_networks[i].severity, weak_networks[i].description, line);

            stats.masvs++;
            if (silent_mode == 1)
            {

                printf(LIGHT_YELLOW "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n" COLOR_RESET, weak_networks[i].name, filepath, line_no, weak_networks[i].severity, weak_networks[i].description, line);
            }
        }
    }

    for (int i = 0; i < masvs_network_security_patterns_count; i++)
    {
        if (strstr(line, network_security_patterns[i].pattern))
        {
            for (int n = 0; n < false_positives_count; n++)
            {
                if (strstr(line, false_positives[n]) != NULL)
                {
                    is_false_positive = 1;
                    break;
                }
            }

            if (!is_false_positive)
            {
                fprintf(for_weak_network, "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n", network_security_patterns[i].name, filepath, line_no, network_security_patterns[i].severity, network_security_patterns[i].description, line);
                stats.masvs++;

                if (silent_mode == 1)
                {
                    printf(LIGHT_YELLOW "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n" COLOR_RESET, network_security_patterns[i].name, filepath, line_no, network_security_patterns[i].severity, network_security_patterns[i].description, line);
                }
            }
        }
    }

    for (int i = 0; i < platform_defense; i++)
    {
        if (strstr(line, platform_defenses[i].pattern))
        {

            fprintf(for_platform_defense,
                    "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n", platform_defenses[i].name, filepath, line_no, platform_defenses[i].severity, platform_defenses[i].description, line);

            stats.masvs++;
            if (silent_mode == 1)
            {

                printf(LIGHT_YELLOW "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n" COLOR_RESET, platform_defenses[i].name, filepath, line_no, platform_defenses[i].severity, platform_defenses[i].description, line);
            }
        }
    }

    for (int i = 0; i < data_storage; i++)
    {
        if (strstr(line, data_storages[i].pattern))
        {

            fprintf(for_data_storage,
                    "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n", data_storages[i].name, filepath, line_no, data_storages[i].severity, data_storages[i].description, line);

            stats.masvs++;
            if (silent_mode == 1)
            {

                printf(LIGHT_YELLOW "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n" COLOR_RESET, data_storages[i].name, filepath, line_no, data_storages[i].severity, data_storages[i].description, line);
            }
        }
    }

    for (int i = 0; i < code_execution; i++)
    {
        if (strstr(line, code_executions[i].pattern))
        {

            fprintf(for_code_execution,
                    "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n", code_executions[i].name, filepath, line_no, code_executions[i].severity, code_executions[i].description, line);

            stats.masvs++;
            if (silent_mode == 1)
            {

                printf(LIGHT_YELLOW "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n" COLOR_RESET, code_executions[i].name, filepath, line_no, code_executions[i].severity, code_executions[i].description, line);
            }
        }
    }

    for (int i = 0; i < web_native; i++)
    {
        if (strstr(line, web_natives[i].pattern))
        {

            fprintf(for_web_native,
                    "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n", web_natives[i].name, filepath, line_no, web_natives[i].severity, web_natives[i].description, line);

            stats.masvs++;
            if (silent_mode == 1)
            {

                printf(LIGHT_YELLOW "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n" COLOR_RESET, web_natives[i].name, filepath, line_no, web_natives[i].severity, web_natives[i].description, line);
            }
        }
    }
}
