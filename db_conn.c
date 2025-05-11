#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <time.h>
#include <sqlite3.h>
#include <sql.h>
#include <sqlext.h>
#include "util.h"
#include "errcode.h"
#include "config_parser.h"
#include "util.h"
#include "log.h"
#include "ssl_conn.h"
#include "db_conn.h"
#include "select_user.h"

extern SQLHENV env;
extern SQLHDBC dbc;

void check_error(SQLRETURN ret, SQLHANDLE handle, SQLSMALLINT type, const char* msg) {
    if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO) return;

    SQLCHAR state[6], message[256];
    SQLINTEGER native;
    SQLSMALLINT len;

    SQLGetDiagRec(type, handle, 1, state, &native, message, sizeof(message), &len);
    LOG(ERROR, "%s\n[SQLSTATE %s] %s\n", msg, state, message);
    exit(1);
}

int init_db(){
    db_connect();
    SQLHSTMT stmt;
    SQLRETURN ret;

    // script 파일 읽기
    FILE* file = fopen(get_config_string("DB_SCRIPT_PATH"), "r");
    if (file == NULL) {
        LOG(ERROR, "DB script file open error");
        return STAT_FAIL;
    }

    fseek(file, 0, SEEK_END);
    long fsize = ftell(file);
    rewind(file);

    char* sql_buf = malloc(fsize + 1);
    if (!sql_buf) {
        LOG(ERROR,"메모리 할당 실패");
        fclose(file);
        return STAT_FAIL;
    }

    fread(sql_buf, 1, fsize, file);
    sql_buf[fsize] = '\0';
    fclose(file);
    file = NULL;
    // 테이블 생성
    ret = SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
    if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) {
        LOG(ERROR, "stmt alloc failed");
        exit(1);
    }
    LOG(DEBUG, "table create sql_buf: %s", sql_buf);
    ret = SQLExecDirect(stmt, (SQLCHAR*)sql_buf, SQL_NTS);
    check_error(ret, stmt, SQL_HANDLE_STMT, "테이블 생성 실패");

#ifdef TEST_PROXY_DB
    // 테스트용 데이터 삽입
    file = fopen("./sql/sqlplus_sample_data.sql", "r");
    if (!file) {
        perror("SQL 파일 열기 실패");
        return 1;
    }

    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        // 세미콜론 제거 및 공백 줄 건너뜀
        LOG(DEBUG, "line: %s\n", line);
        char* trimmed = strtok(line, ";\n");
        if (!trimmed || strlen(trimmed) == 0) continue;
        ret = SQLExecDirect(stmt, (SQLCHAR*)trimmed, SQL_NTS);
        check_error(ret, stmt, SQL_HANDLE_STMT, "SQL 실행 실패");
        LOG(DEBUG, "실행 완료: %s\n", trimmed);
    }

    select_user(stmt);
    url_policy_list_t *url_policy_list = NULL;
    select_policy_by_user_id(stmt, "user001",&url_policy_list);
    while(url_policy_list != NULL)
    {
        LOG(DEBUG, "url: %s\n", url_policy_list->url);
        url_policy_list_t *temp = url_policy_list;
        url_policy_list = url_policy_list->next;
        free(temp);
    }
#endif

    LOG(DEBUG, "초기 SQLite shared memory DB 및 테이블 생성 완료");

    return STAT_OK;
}
//get_config_string("DB_SCRIPT_PATH")

void print_user_table(SQLHSTMT stmt) {
    SQLRETURN ret;
    SQLCHAR id[64], pw[21],name[64], phone[32], email[128];
    SQLINTEGER policy_id;

    const char* query = "SELECT user_id, user_pw,user_name, user_phone, user_email, policy_id FROM User;";
    ret = SQLExecDirect(stmt, (SQLCHAR*)query, SQL_NTS);
    check_error(ret, stmt, SQL_HANDLE_STMT, "User SELECT 실패");

    LOG(DEBUG, "=== User Table ===");
    while ((ret = SQLFetch(stmt)) != SQL_NO_DATA) {
        SQLGetData(stmt, 1, SQL_C_CHAR, id, sizeof(id), NULL);
        SQLGetData(stmt, 2, SQL_C_CHAR, pw, sizeof(pw), NULL);
        SQLGetData(stmt, 3, SQL_C_CHAR, name, sizeof(name), NULL);
        SQLGetData(stmt, 4, SQL_C_CHAR, phone, sizeof(phone), NULL);
        SQLGetData(stmt, 5, SQL_C_CHAR, email, sizeof(email), NULL);
        SQLGetData(stmt, 6, SQL_C_SLONG, &policy_id, 0, NULL);

        LOG(DEBUG, "user_id: %s, pw: %s,name: %s, phone: %s, email: %s, policy_id: %d",
               id, pw,name, phone, email, policy_id);
    }

    SQLCloseCursor(stmt);
}

int db_connect() {
    SQLRETURN ret;
/*
    SQLHENV env;
    SQLHDBC dbc;*/
    env = NULL;
    dbc = NULL;

    // 1. 환경 핸들 할당
    ret = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env);
    if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) {
        LOG(ERROR, "DB 환경 할당 실패");
        return STAT_FAIL;
    }

    // 2. ODBC 버전 설정
    ret = SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (void*)SQL_OV_ODBC3, 0);
    if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) {
        LOG(ERROR, "ODBC 버전 설정 실패");
        SQLFreeHandle(SQL_HANDLE_ENV, env);
        env = NULL;
        return STAT_FAIL;
    }

    // 3. DBC 핸들 할당
    ret = SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc);
    if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) {
        LOG(ERROR, "DB 연결 핸들 할당 실패");
        SQLFreeHandle(SQL_HANDLE_ENV, env);
        env = NULL;
        return STAT_FAIL;
    }

    // 4. DSN-less DB 연결
    const char* connStr = "DRIVER=SQLite3;DATABASE=file:sharedmem?mode=memory&cache=shared;";
    ret = SQLDriverConnect(dbc, NULL, (SQLCHAR*)connStr, SQL_NTS,
                           NULL, 0, NULL, SQL_DRIVER_COMPLETE);
    if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) {
        LOG(ERROR, "DB 연결 실패");
        SQLFreeHandle(SQL_HANDLE_DBC, dbc);
        SQLFreeHandle(SQL_HANDLE_ENV, env);
        dbc = NULL;
        env = NULL;
        return STAT_FAIL;
    }

    return STAT_OK;
}
