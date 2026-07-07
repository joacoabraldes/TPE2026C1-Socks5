#include <string.h>
#include "users.h"

struct user {
    bool used;
    char name[USERS_MAX_NAME + 1];
    char pass[USERS_MAX_PASS + 1];
};

static struct user db[USERS_MAX];

void users_init(void) {
    memset(db, 0, sizeof(db));
}

static int find(const char *name) {
    for (int i = 0; i < USERS_MAX; i++) {
        if (db[i].used && strcmp(db[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

static bool valid_field(const char *s, size_t max) {
    if (s == NULL) {
        return false;
    }
    size_t n = strlen(s);
    return n > 0 && n <= max;
}

enum users_result users_add(const char *name, const char *pass) {
    if (!valid_field(name, USERS_MAX_NAME) || !valid_field(pass, USERS_MAX_PASS)) {
        return USERS_INVALID;
    }
    int idx = find(name);
    if (idx >= 0) {
        /* actualiza contraseña de un usuario existente */
        strcpy(db[idx].pass, pass);
        return USERS_OK;
    }
    for (int i = 0; i < USERS_MAX; i++) {
        if (!db[i].used) {
            db[i].used = true;
            strcpy(db[i].name, name);
            strcpy(db[i].pass, pass);
            return USERS_OK;
        }
    }
    return USERS_FULL;
}

enum users_result users_del(const char *name) {
    if (name == NULL) {
        return USERS_INVALID;
    }
    int idx = find(name);
    if (idx < 0) {
        return USERS_NOT_FOUND;
    }
    memset(&db[idx], 0, sizeof(db[idx]));
    return USERS_OK;
}

bool users_check(const char *name, const char *pass) {
    if (name == NULL || pass == NULL) {
        return false;
    }
    int idx = find(name);
    if (idx < 0) {
        return false;
    }
    return strcmp(db[idx].pass, pass) == 0;
}

bool users_exists(const char *name) {
    return name != NULL && find(name) >= 0;
}

size_t users_count(void) {
    size_t c = 0;
    for (int i = 0; i < USERS_MAX; i++) {
        if (db[i].used) {
            c++;
        }
    }
    return c;
}

const char *users_name_at(size_t i) {
    size_t c = 0;
    for (int j = 0; j < USERS_MAX; j++) {
        if (db[j].used) {
            if (c == i) {
                return db[j].name;
            }
            c++;
        }
    }
    return NULL;
}
