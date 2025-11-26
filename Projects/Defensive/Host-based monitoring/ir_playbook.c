/**
 * Incident Response Playbook - C Implementation
 * Basic incident tracking and response procedures
 * Compile: gcc -o ir_playbook ir_playbook.c -lsqlite3
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>
#include <unistd.h>
#include <sys/stat.h>

#define MAX_INCIDENTS 100
#define MAX_ACTIONS 1000
#define MAX_PATH 256

typedef struct {
    char incident_id[50];
    char title[100];
    char severity[20];
    char type[50];
    char status[20];
    time_t created_at;
    time_t updated_at;
} Incident;

typedef struct {
    char incident_id[50];
    char action_type[50];
    char description[200];
    time_t timestamp;
    char status[20];
} IncidentAction;

typedef struct {
    Incident incidents[MAX_INCIDENTS];
    int incident_count;
    IncidentAction actions[MAX_ACTIONS];
    int action_count;
    sqlite3* db;
} IncidentManager;

void generate_incident_id(char* buffer, size_t size) {
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    
    snprintf(buffer, size, "INC-%04d%02d%02d-%06ld", 
             tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
             random() % 1000000);
}

int init_database(IncidentManager* manager) {
    int rc = sqlite3_open("incidents.db", &manager->db);
    if(rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(manager->db));
        return 0;
    }
    
    char* sql = "CREATE TABLE IF NOT EXISTS incidents ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "incident_id TEXT UNIQUE NOT NULL,"
                "title TEXT NOT NULL,"
                "severity TEXT NOT NULL,"
                "type TEXT NOT NULL,"
                "status TEXT NOT NULL,"
                "created_at INTEGER,"
                "updated_at INTEGER);";
    
    char* err_msg = 0;
    rc = sqlite3_exec(manager->db, sql, 0, 0, &err_msg);
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return 0;
    }
    
    sql = "CREATE TABLE IF NOT EXISTS incident_actions ("
          "id INTEGER PRIMARY KEY AUTOINCREMENT,"
          "incident_id TEXT NOT NULL,"
          "action_type TEXT NOT NULL,"
          "description TEXT,"
          "timestamp INTEGER,"
          "status TEXT);";
    
    rc = sqlite3_exec(manager->db, sql, 0, 0, &err_msg);
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return 0;
    }
    
    return 1;
}

int create_incident(IncidentManager* manager, const char* title, const char* severity, const char* type) {
    Incident incident;
    generate_incident_id(incident.incident_id, sizeof(incident.incident_id));
    
    strncpy(incident.title, title, sizeof(incident.title) - 1);
    strncpy(incident.severity, severity, sizeof(incident.severity) - 1);
    strncpy(incident.type, type, sizeof(incident.type) - 1);
    strcpy(incident.status, "open");
    
    time_t now = time(NULL);
    incident.created_at = now;
    incident.updated_at = now;
    
    // Store in database
    char sql[512];
    snprintf(sql, sizeof(sql),
             "INSERT INTO incidents (incident_id, title, severity, type, status, created_at, updated_at) "
             "VALUES ('%s', '%s', '%s', '%s', '%s', %ld, %ld);",
             incident.incident_id, incident.title, incident.severity, incident.type, 
             incident.status, incident.created_at, incident.updated_at);
    
    char* err_msg = 0;
    int rc = sqlite3_exec(manager->db, sql, 0, 0, &err_msg);
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return 0;
    }
    
    // Log initial action
    char action_sql[512];
    snprintf(action_sql, sizeof(action_sql),
             "INSERT INTO incident_actions (incident_id, action_type, description, timestamp, status) "
             "VALUES ('%s', 'incident_created', 'Incident created: %s', %ld, 'completed');",
             incident.incident_id, incident.title, now);
    
    sqlite3_exec(manager->db, action_sql, 0, 0, 0);
    
    printf("Created incident: %s\n", incident.incident_id);
    return 1;
}

void log_action(IncidentManager* manager, const char* incident_id, const char* action_type, const char* description) {
    char sql[512];
    time_t now = time(NULL);
    
    snprintf(sql, sizeof(sql),
             "INSERT INTO incident_actions (incident_id, action_type, description, timestamp, status) "
             "VALUES ('%s', '%s', '%s', %ld, 'completed');",
             incident_id, action_type, description, now);
    
    sqlite3_exec(manager->db, sql, 0, 0, 0);
    
    printf("[%s] %s: %s\n", incident_id, action_type, description);
}

int execute_malware_playbook(IncidentManager* manager, const char* incident_id) {
    printf("Executing malware response playbook for %s\n", incident_id);
    
    const char* steps[] = {
        "containment_immediate",
        "evidence_collection", 
        "malware_analysis",
        "eradication",
        "recovery",
        "post_incident",
        NULL
    };
    
    for(int i = 0; steps[i] != NULL; i++) {
        char description[100];
        snprintf(description, sizeof(description), "Executing step: %s", steps[i]);
        log_action(manager, incident_id, "playbook_step", description);
        
        // Simulate step execution
        sleep(1);
    }
    
    // Update incident status
    char sql[256];
    snprintf(sql, sizeof(sql), 
             "UPDATE incidents SET status = 'contained', updated_at = %ld WHERE incident_id = '%s';",
             time(NULL), incident_id);
    sqlite3_exec(manager->db, sql, 0, 0, 0);
    
    return 1;
}

void list_incidents(IncidentManager* manager, const char* status_filter) {
    char sql[256];
    if(status_filter) {
        snprintf(sql, sizeof(sql), 
                 "SELECT incident_id, title, severity, status FROM incidents WHERE status = '%s' ORDER BY created_at DESC;",
                 status_filter);
    } else {
        strcpy(sql, "SELECT incident_id, title, severity, status FROM incidents ORDER BY created_at DESC;");
    }
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(manager->db, sql, -1, &stmt, 0);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "Failed to execute query: %s\n", sqlite3_errmsg(manager->db));
        return;
    }
    
    printf("Incidents:\n");
    printf("----------\n");
    
    while(sqlite3_step(stmt) == SQLITE_ROW) {
        const char* incident_id = (const char*)sqlite3_column_text(stmt, 0);
        const char* title = (const char*)sqlite3_column_text(stmt, 1);
        const char* severity = (const char*)sqlite3_column_text(stmt, 2);
        const char* status = (const char*)sqlite3_column_text(stmt, 3);
        
        printf("%s: %s (%s) - %s\n", incident_id, title, severity, status);
    }
    
    sqlite3_finalize(stmt);
}

void generate_incident_report(IncidentManager* manager, const char* incident_id) {
    // Get incident details
    char sql[256];
    snprintf(sql, sizeof(sql),
             "SELECT title, severity, type, status, created_at FROM incidents WHERE incident_id = '%s';",
             incident_id);
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(manager->db, sql, -1, &stmt, 0);
    
    if(rc != SQLITE_OK || sqlite3_step(stmt) != SQLITE_ROW) {
        printf("Incident not found: %s\n", incident_id);
        return;
    }
    
    const char* title = (const char*)sqlite3_column_text(stmt, 0);
    const char* severity = (const char*)sqlite3_column_text(stmt, 1);
    const char* type = (const char*)sqlite3_column_text(stmt, 2);
    const char* status = (const char*)sqlite3_column_text(stmt, 3);
    time_t created_at = sqlite3_column_int(stmt, 4);
    
    sqlite3_finalize(stmt);
    
    // Get actions
    snprintf(sql, sizeof(sql),
             "SELECT action_type, description, timestamp FROM incident_actions "
             "WHERE incident_id = '%s' ORDER BY timestamp;", incident_id);
    
    rc = sqlite3_prepare_v2(manager->db, sql, -1, &stmt, 0);
    
    printf("\nINCIDENT REPORT\n");
    printf("===============\n\n");
    
    printf("Incident: %s\n", incident_id);
    printf("Title: %s\n", title);
    printf("Type: %s\n", type);
    printf("Severity: %s\n", severity);
    printf("Status: %s\n", status);
    printf("Created: %s", ctime(&created_at));
    
    printf("\nTimeline:\n");
    printf("---------\n");
    
    while(sqlite3_step(stmt) == SQLITE_ROW) {
        const char* action_type = (const char*)sqlite3_column_text(stmt, 0);
        const char* description = (const char*)sqlite3_column_text(stmt, 1);
        time_t timestamp = sqlite3_column_int(stmt, 2);
        
        printf("%s: %s - %s\n", ctime(&timestamp), action_type, description);
    }
    
    sqlite3_finalize(stmt);
}

void print_usage() {
    printf("Incident Response Playbook\n");
    printf("Usage:\n");
    printf("  create <title> <severity> <type>    - Create new incident\n");
    printf("  list [status]                       - List incidents\n");
    printf("  playbook <incident_id> <type>       - Execute playbook\n");
    printf("  report <incident_id>                - Generate report\n");
    printf("  help                                - Show this help\n");
}

int main(int argc, char* argv[]) {
    if(argc < 2) {
        print_usage();
        return 1;
    }
    
    srand(time(NULL));
    
    IncidentManager manager;
    if(!init_database(&manager)) {
        return 1;
    }
    
    if(strcmp(argv[1], "create") == 0 && argc >= 5) {
        create_incident(&manager, argv[2], argv[3], argv[4]);
    }
    else if(strcmp(argv[1], "list") == 0) {
        const char* status_filter = argc > 2 ? argv[2] : NULL;
        list_incidents(&manager, status_filter);
    }
    else if(strcmp(argv[1], "playbook") == 0 && argc >= 4) {
        if(strcmp(argv[3], "malware") == 0) {
            execute_malware_playbook(&manager, argv[2]);
        } else {
            printf("Unknown playbook type: %s\n", argv[3]);
        }
    }
    else if(strcmp(argv[1], "report") == 0 && argc >= 3) {
        generate_incident_report(&manager, argv[2]);
    }
    else if(strcmp(argv[1], "help") == 0) {
        print_usage();
    }
    else {
        printf("Unknown command: %s\n", argv[1]);
        print_usage();
        return 1;
    }
    
    sqlite3_close(manager.db);
    return 0;
}
