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
void select_user(SQLHSTMT stmt) {
    SQLRETURN ret;
    SQLCHAR id[64], pw[21],name[64], phone[32], email[128];
    SQLINTEGER policy_id;

    const char* query = "SELECT user_id, user_pw,user_name, user_phone, user_email, policy_id FROM User;";
    ret = SQLExecDirect(stmt, (SQLCHAR*)query, SQL_NTS);
    check_error(ret, stmt, SQL_HANDLE_STMT, "User SELECT 실패");

    LOG(DEBUG, "=== User Table ===\n");
    while ((ret = SQLFetch(stmt)) != SQL_NO_DATA) {
        SQLGetData(stmt, 1, SQL_C_CHAR, id, sizeof(id), NULL);
        SQLGetData(stmt, 2, SQL_C_CHAR, pw, sizeof(pw), NULL);
        SQLGetData(stmt, 3, SQL_C_CHAR, name, sizeof(name), NULL);
        SQLGetData(stmt, 4, SQL_C_CHAR, phone, sizeof(phone), NULL);
        SQLGetData(stmt, 5, SQL_C_CHAR, email, sizeof(email), NULL);
        SQLGetData(stmt, 6, SQL_C_SLONG, &policy_id, 0, NULL);

        LOG(DEBUG,"user_id: %s, pw: %s,name: %s, phone: %s, email: %s, policy_id: %d\n",
               id, pw,name, phone, email, policy_id);
    }

    SQLCloseCursor(stmt);
}

int select_policy_by_user_id(SQLHSTMT stmt, const char* user_id, url_policy_list_t **url_policy_list) {
    SQLRETURN ret;
    SQLCHAR url[64];
    int result=0;

    // 사용자 ID에 해당하는 정책 조회
    const char* query = "SELECT url.url_pattern FROM User u JOIN Policy_URL pu ON u.policy_id = pu.policy_id JOIN URL url ON pu.url_id = url.url_id WHERE u.user_id = ?;";
    SQLFreeStmt(stmt, SQL_CLOSE); // 이전 결과셋 정리 
    ret = SQLPrepare(stmt, (SQLCHAR*)query, SQL_NTS);
    check_error(ret, stmt, SQL_HANDLE_STMT, "정책 조회 준비 실패");

    ret = SQLBindParameter(stmt, 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_CHAR, 0, 0, (SQLCHAR*)user_id, 0, NULL);
    check_error(ret, stmt, SQL_HANDLE_STMT, "정책 조회 바인딩 실패");

    ret = SQLExecute(stmt);
    check_error(ret, stmt, SQL_HANDLE_STMT, "정책 조회 실행 실패");

    // url_policy_list가 NULL인 경우 가정 - TODO
    *url_policy_list = (url_policy_list_t *)malloc(sizeof(url_policy_list_t));
    (*url_policy_list)->next = NULL;
    url_policy_list_t *url_policy = *url_policy_list;
    
    
    LOG(DEBUG, "=== User Policy ===");
    ret = SQLFetch(stmt);
    while (ret != SQL_NO_DATA) {
        result++;
        SQLGetData(stmt, 1, SQL_C_CHAR, url, sizeof(url), NULL);
        LOG(DEBUG, "select_policy_by_user_id url: %s", url);
        sprintf(url_policy->url, "%s", url);
        if((ret = SQLFetch(stmt))!= SQL_NO_DATA){
            url_policy->next = (url_policy_list_t *)malloc(sizeof(url_policy_list_t));
            url_policy = url_policy->next;
            url_policy->next = NULL;
        }
    }

    SQLCloseCursor(stmt);
    return result;
}

int count_user_by_user_id_user_pw(SQLHSTMT stmt, const char* user_id, const char* user_pw) {
    SQLRETURN ret;
    SQLINTEGER count = 0;

    // 사용자 ID와 비밀번호로 사용자 수 조회
    const char* query = "SELECT COUNT(*) FROM User WHERE user_id = ? AND user_pw = ? COLLATE NOCASE;";
    ret = SQLPrepare(stmt, (SQLCHAR*)query, SQL_NTS);
    check_error(ret, stmt, SQL_HANDLE_STMT, "사용자 수 조회 준비 실패");

    ret = SQLBindParameter(stmt, 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_CHAR, 0, 0, (SQLCHAR*)user_id, 0, NULL);
    check_error(ret, stmt, SQL_HANDLE_STMT, "사용자 수 조회 바인딩 실패");

    ret = SQLBindParameter(stmt, 2, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_CHAR, 0, 0, (SQLCHAR*)user_pw, 0, NULL);
    check_error(ret, stmt, SQL_HANDLE_STMT, "사용자 수 조회 바인딩 실패");

    ret = SQLExecute(stmt);
    check_error(ret, stmt, SQL_HANDLE_STMT, "사용자 수 조회 실행 실패");

    ret = SQLFetch(stmt);
    if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO) {
        SQLGetData(stmt, 1, SQL_C_SLONG, &count, sizeof(count), NULL);
        LOG(ERROR, "count_user_by_user_id_user_pw count: %d", count);
    }
    SQLCloseCursor(stmt);
    return count;
}