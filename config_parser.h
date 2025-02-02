#ifndef CONFIG_PARSER
#define CONFIG_PARSER

#define MAX_LINE 256
#define MAX_CONFIGS 100
#define CONFIG_FILE "config.txt"
const char *get_config_string(const char *key);
int get_config_int(const char *key);
int load_config();
void print_config();
#endif