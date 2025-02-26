#ifndef LOG_HEADER
#define LOG_HEADER
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

// 로그 레벨 정의
typedef enum {
    TRACE,
    DEBUG,
    INFO,
    WARN,
    ERROR
} LogLevel;

// 매크로로 파일명 및 라인 번호 자동 추가
#define LOG(level, ...) log_message(level, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_TRACE(...) LOG(TRACE, __VA_ARGS__)
#define LOG_DEBUG(...) LOG(DEBUG, __VA_ARGS__)
#define LOG_INFO(...)  LOG(INFO,  __VA_ARGS__)
#define LOG_WARN(...)  LOG(WARN,  __VA_ARGS__)
#define LOG_ERROR(...) LOG(ERROR, __VA_ARGS__)
void log_message(LogLevel level, const char *file, int line, const char *format, ...);
void init_log_file(const char *filename);
void set_log_level(LogLevel level);
void close_log_file();
#endif