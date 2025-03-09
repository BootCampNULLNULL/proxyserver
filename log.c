#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>

#include "log.h"

#define LOG_FILE "log"   // 로그 파일 경로
#define MAX_LOG_MESSAGE 4096   // 최대 로그 메시지 길이


static LogLevel current_log_level = TRACE;  // 기본 로그 레벨
static FILE *log_fp = NULL;  // 로그 파일 포인터

// 로그 레벨을 문자열로 변환
const char *log_level_to_string(LogLevel level) {
    switch (level) {
        case TRACE: return "TRACE";
        case DEBUG: return "DEBUG";
        case INFO:  return "INFO";
        case WARN:  return "WARN";
        case ERROR: return "ERROR";
        default:    return "UNKNOWN";
    }
}



// 로그 출력 함수 (vsnprintf 사용하여 포맷 지원)
void log_message(LogLevel level, const char *file, int line, const char *format, ...) {
    if (level < current_log_level) return;  // 설정된 로그 레벨보다 낮으면 무시

    char timestamp[20];
    char log_file[20];
    char log_msg[MAX_LOG_MESSAGE];
    // 
    time_t now  = time(NULL);
    struct tm *t = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);
    strftime(log_file, sizeof(log_file), "%Y-%m-%d", t);
    sprintf(log_file+strlen(log_file),"_log");
    init_log_file(log_file);
    va_list args;
    va_start(args, format);
    vsnprintf(log_msg, sizeof(log_msg), format, args);  // 가변 인자 포맷팅
    va_end(args);
    pid_t pid = getpid();  // 프로세스 ID 가져오기
    pthread_t tid = pthread_self();  // 스레드 ID 가져오기

    // 파일 출력
    if (log_fp) {
        fprintf(log_fp, "[%s][%s](p:%d t:%lu)(%s:%d) %s\n", log_level_to_string(level), timestamp, pid, tid/10000000,file, line, log_msg);
        fflush(log_fp);
    }
}

// 로그 레벨 변경 함수
void set_log_level(LogLevel level) {
    current_log_level = level;
}

// 로그 파일 초기화
void init_log_file(const char *filename) {
    log_fp = fopen(filename, "a");
    if (!log_fp) {
        perror("Failed to open log file");
    }
}

// 로그 시스템 종료
void close_log_file() {
    if (log_fp) {
        fclose(log_fp);
        log_fp = NULL;
    }
}
