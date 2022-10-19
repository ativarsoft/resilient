#ifndef RESILIENT_H
#define RESILIENT_H

int set_config_option_string(const char *name, const char *value);
int set_config_option_int(const char *name, int value);

int read_config_file();

#endif
