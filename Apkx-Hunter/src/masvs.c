/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

#include "masvs.h"


void scan_masvs_1(const char *filepath, FILE *for_masvs, char *line, int line_no)
{
    int is_false_positive = 0;

    for (int i = 0; i < masvs_count; i++)
    {
        if (strstr(line, masvs_patterns[i].pattern))
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
                fprintf(for_masvs,
                        "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n", masvs_patterns[i].name, filepath, line_no, masvs_patterns[i].severity, masvs_patterns[i].description, line);

                    stats.masvs++;
                if (silent_mode == 1)
                {

                    printf(LIGHT_YELLOW "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n" COLOR_RESET, masvs_patterns[i].name, filepath, line_no, masvs_patterns[i].severity, masvs_patterns[i].description, line);
                }
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
                fprintf(for_masvs, "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n", network_security_patterns[i].name, filepath, line_no, network_security_patterns[i].severity, network_security_patterns[i].description, line);
                stats.masvs++;

                if (silent_mode == 1)
                {
                    printf(LIGHT_YELLOW "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n" COLOR_RESET, network_security_patterns[i].name, filepath, line_no, network_security_patterns[i].severity, network_security_patterns[i].description, line);
                }
            }
        }
    }
}

void scan_masvs(const char *filepath, FILE *for_masvs, char *line, int line_no)
{
    int is_false_positive = 0;


    scan_buckets(filepath, for_masvs, line, count_patterns, line_no);
    scan_secrets(filepath, for_masvs, line, count_secrets, line_no);
    scan_strings_xml(filepath, for_masvs, line, line_no);

    for (int i = 0; i < masvs_count; i++)
    {
        if (strstr(line, masvs_patterns[i].pattern))
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
                fprintf(for_masvs,
                        "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n", masvs_patterns[i].name, filepath, line_no, masvs_patterns[i].severity, masvs_patterns[i].description, line);

                        stats.masvs++;
                if (silent_mode == 1)
                {
                    printf(LIGHT_YELLOW "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n" COLOR_RESET, masvs_patterns[i].name, filepath, line_no, masvs_patterns[i].severity, masvs_patterns[i].description, line);
                }
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
                fprintf(for_masvs,
                        "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n", network_security_patterns[i].name, filepath, line_no, network_security_patterns[i].severity, network_security_patterns[i].description, line);

                        stats.masvs++;
                if (silent_mode == 1)
                {
                    printf(LIGHT_YELLOW "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n" COLOR_RESET, network_security_patterns[i].name, filepath, line_no, network_security_patterns[i].severity, network_security_patterns[i].description, line);
                }
            }
        }
    }
}

