#ifndef _INIT_DB_H
#define _INIT_DB_H

#include <sqlite3.h>
#include <sql.h>
#include <sqlext.h>

typedef struct {
    SQLHENV env;
    SQLHDBC dbc;
    SQLHSTMT stmt;
} db_context_t;

int init_db();
void check_error(SQLRETURN ret, SQLHANDLE handle, SQLSMALLINT type, const char* msg);
int db_connect();
#endif