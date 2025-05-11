#ifndef __SELECT_USER_H__
#define __SELECT_USER_H__
#include <sqlite3.h>
#include <sql.h>
#include <sqlext.h>
typedef struct url_policy_list{
    char url[64];
    struct url_policy_list *next;
}url_policy_list_t;

void select_user(SQLHSTMT stmt);
int select_policy_by_user_id(SQLHSTMT stmt, const char* user_id, url_policy_list_t **url_policy_list);
int count_user_by_user_id_user_pw(SQLHSTMT stmt, const char* user_id, const char* user_pw);
#endif