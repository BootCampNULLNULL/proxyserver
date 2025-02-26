#ifndef UTIL_H
#define UTIL_H
#include <time.h>
int init_proxy();
int set_current_time(time_t *cur_time);
int check_valid_time(time_t *start_time);
#endif