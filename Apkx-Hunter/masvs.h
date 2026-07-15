#ifndef MASVS_H
#define MASVS_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

int masvs_count = sizeof(masvs_patterns) / sizeof(masvs_patterns[0]);
int masvs_network_security_patterns_count = sizeof(network_security_patterns) / sizeof(network_security_patterns[0]);
int false_positives_count = sizeof(false_positives) / sizeof(false_positives[0]);

#include "scan_secrets.h"
#include "patterns.h"
#include "define.h"
#include "file_making.h"

// MASVS SCANNING FUNCTION

void scan_masvs_1(const char *filepath, FILE *for_masvs, char *line, int line_no)
{
    int is_false_positive = 0;
    

    for (int i = 0; i < masvs_count; i++)
    {
        if (strstr(line, masvs_patterns[i].pattern))
        {
            fprintf(for_masvs,
                    "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n", masvs_patterns[i].name, filepath, line_no, masvs_patterns[i].severity, masvs_patterns[i].description, line);

            printf(LIGHT_YELLOW "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n" COLOR_RESET, masvs_patterns[i].name, filepath, line_no, masvs_patterns[i].severity, masvs_patterns[i].description, line);
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
                        "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n", masvs_patterns[i].name, filepath, line_no, masvs_patterns[i].severity, masvs_patterns[i].description, line);

                printf(LIGHT_YELLOW "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n" COLOR_RESET, masvs_patterns[i].name, filepath, line_no, masvs_patterns[i].severity, masvs_patterns[i].description, line);
            }
        }
    }

   
}

void scan_masvs(const char *filepath, FILE *for_masvs, char *line, int line_no)
{
    int is_false_positive = 0;
    

    int bucket_count =
        sizeof(Bucket) / sizeof(Bucket[0]);

    int count_secrets = sizeof(secrets) / sizeof(secrets[0]);

    scan_buckets(filepath, for_masvs, line, bucket_count, line_no);
    scan_secrets(filepath, for_masvs, line, count_secrets, line_no);
    scan_strings_xml(filepath, for_masvs, line, line_no);

    for (int i = 0; i < masvs_count; i++)
    {
        if (strstr(line, masvs_patterns[i].pattern))
        {
            fprintf(for_masvs,
                    "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n", masvs_patterns[i].name, filepath, line_no, masvs_patterns[i].severity, masvs_patterns[i].description, line);

            printf(LIGHT_YELLOW "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n" COLOR_RESET, masvs_patterns[i].name, filepath, line_no, masvs_patterns[i].severity, masvs_patterns[i].description, line);
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
                        "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n", masvs_patterns[i].name, filepath, line_no, masvs_patterns[i].severity, masvs_patterns[i].description, line);

                printf(LIGHT_YELLOW "[%s]\nFilePath %s:%d \tSEVERITY = %s\nDESCRIPTION: %s\nFOUND: %s\n" COLOR_RESET, masvs_patterns[i].name, filepath, line_no, masvs_patterns[i].severity, masvs_patterns[i].description, line);
            }
        }
    }

    
}

#endif
