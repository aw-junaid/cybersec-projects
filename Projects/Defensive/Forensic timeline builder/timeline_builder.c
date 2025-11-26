/**
 * Forensic Timeline Builder - C Implementation
 * Basic timeline construction and event correlation
 * Compile: gcc -o timeline_builder timeline_builder.c -lsqlite3
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_EVENTS 10000
#define MAX_PATH 1024
#define MAX_DESCRIPTION 500

typedef struct {
    time_t timestamp;
    char source[50];
    char event_type[50];
    char description[MAX_DESCRIPTION];
    char artifact[MAX_PATH];
    char user[100];
    char host[100];
} TimelineEvent;

typedef struct {
    TimelineEvent events[MAX_EVENTS];
    int count;
    sqlite3* db;
} TimelineBuilder;

void init_database(TimelineBuilder* builder, const char* case_name) {
    char db_path[MAX_PATH];
    snprintf(db_path, sizeof(db_path), "%s_timeline.db", case_name);
    
    int rc = sqlite3_open(db_path, &builder->db);
    if(rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(builder->db));
        return;
    }
    
    char* sql = "CREATE TABLE IF NOT EXISTS timeline_events ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "timestamp INTEGER NOT NULL,"
                "source TEXT NOT NULL,"
                "event_type TEXT NOT NULL,"
                "description TEXT NOT NULL,"
                "artifact TEXT,"
                "user TEXT,"
                "host TEXT);";
    
    char* err_msg = 0;
    rc = sqlite3_exec(builder->db, sql, 0, 0, &err_msg);
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
    }
    
    builder->count = 0;
}

void add_event(TimelineBuilder* builder, const TimelineEvent* event) {
    if(builder->count >= MAX_EVENTS) {
        printf("Warning: Event limit reached\n");
        return;
    }
    
    builder->events[builder->count] = *event;
    builder->count++;
    
    // Also store in database
    char sql[1024];
    snprintf(sql, sizeof(sql),
             "INSERT INTO timeline_events (timestamp, source, event_type, description, artifact, user, host) "
             "VALUES (%ld, '%s', '%s', '%s', '%s', '%s', '%s');",
             event->timestamp, event->source, event->event_type, event->description,
             event->artifact, event->user, event->host);
    
    char* err_msg = 0;
    int rc = sqlite3_exec(builder->db, sql, 0, 0, &err_msg);
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
    }
}

void process_filesystem_timestamps(TimelineBuilder* builder, const char* directory) {
    printf("Processing filesystem timestamps from: %s\n", directory);
    
    DIR* dir = opendir(directory);
    if(!dir) {
        printf("Error: Cannot open directory %s\n", directory);
        return;
    }
    
    struct dirent* entry;
    char full_path[MAX_PATH];
    
    while((entry = readdir(dir)) != NULL) {
        if(strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        snprintf(full_path, sizeof(full_path), "%s/%s", directory, entry->d_name);
        
        struct stat st;
        if(stat(full_path, &st) == 0) {
            // Create events for different timestamp types
            TimelineEvent events[3];
            
            // Modified time
            events[0].timestamp = st.st_mtime;
            strcpy(events[0].source, "filesystem");
            strcpy(events[0].event_type, "file_modified");
            snprintf(events[0].description, sizeof(events[0].description), "File modified: %s", full_path);
            strcpy(events[0].artifact, full_path);
            strcpy(events[0].user, "");
            strcpy(events[0].host, "");
            
            // Accessed time
            events[1].timestamp = st.st_atime;
            strcpy(events[1].source, "filesystem");
            strcpy(events[1].event_type, "file_accessed");
            snprintf(events[1].description, sizeof(events[1].description), "File accessed: %s", full_path);
            strcpy(events[1].artifact, full_path);
            strcpy(events[1].user, "");
            strcpy(events[1].host, "");
            
            // Changed time
            events[2].timestamp = st.st_ctime;
            strcpy(events[2].source, "filesystem");
            strcpy(events[2].event_type, "metadata_changed");
            snprintf(events[2].description, sizeof(events[2].description), "File metadata changed: %s", full_path);
            strcpy(events[2].artifact, full_path);
            strcpy(events[2].user, "");
            strcpy(events[2].host, "");
            
            for(int i = 0; i < 3; i++) {
                add_event(builder, &events[i]);
            }
        }
    }
    
    closedir(dir);
    printf("Processed filesystem events from %s\n", directory);
}

void generate_timeline_report(TimelineBuilder* builder, const char* output_file) {
    printf("Generating timeline report...\n");
    
    FILE* fp = output_file ? fopen(output_file, "w") : stdout;
    if(!fp) {
        printf("Error: Cannot open output file\n");
        return;
    }
    
    fprintf(fp, "Forensic Timeline Report\n");
    fprintf(fp, "=======================\n\n");
    
    fprintf(fp, "Generated: %s", ctime(&(time_t){time(NULL)}));
    fprintf(fp, "Total Events: %d\n\n", builder->count);
    
    // Sort events by timestamp (simple bubble sort for demo)
    for(int i = 0; i < builder->count - 1; i++) {
        for(int j = 0; j < builder->count - i - 1; j++) {
            if(builder->events[j].timestamp > builder->events[j + 1].timestamp) {
                TimelineEvent temp = builder->events[j];
                builder->events[j] = builder->events[j + 1];
                builder->events[j + 1] = temp;
            }
        }
    }
    
    fprintf(fp, "Timeline Events:\n");
    fprintf(fp, "----------------\n");
    
    for(int i = 0; i < builder->count && i < 100; i++) { // Show first 100 events
        TimelineEvent* event = &builder->events[i];
        fprintf(fp, "%s", ctime(&event->timestamp));
        fprintf(fp, "  [%s/%s] %s\n", event->source, event->event_type, event->description);
        fprintf(fp, "  Artifact: %s\n", event->artifact);
        if(strlen(event->user) > 0) {
            fprintf(fp, "  User: %s\n", event->user);
        }
        fprintf(fp, "\n");
    }
    
    if(builder->count > 100) {
        fprintf(fp, "... and %d more events\n", builder->count - 100);
    }
    
    if(output_file) {
        fclose(fp);
        printf("Report saved to: %s\n", output_file);
    }
}

void correlate_events(TimelineBuilder* builder, int time_window_seconds) {
    printf("Correlating events within %d second window...\n", time_window_seconds);
    
    int correlated_groups = 0;
    
    for(int i = 0; i < builder->count; i++) {
        TimelineEvent* current = &builder->events[i];
        int group_size = 1;
        
        // Look ahead for events within time window
        for(int j = i + 1; j < builder->count; j++) {
            TimelineEvent* next = &builder->events[j];
            time_t time_diff = next->timestamp - current->timestamp;
            
            if(time_diff <= time_window_seconds) {
                group_size++;
            } else {
                break;
            }
        }
        
        if(group_size > 1) {
            correlated_groups++;
            printf("Correlated group %d: %d events around %s", 
                   correlated_groups, group_size, ctime(&current->timestamp));
        }
        
        // Skip events we've already processed in this group
        i += group_size - 1;
    }
    
    printf("Found %d correlated event groups\n", correlated_groups);
}

void print_usage() {
    printf("Forensic Timeline Builder\n");
    printf("Usage:\n");
    printf("  build <case_name> <directory>    - Build timeline from filesystem\n");
    printf("  report <case_name> [output_file] - Generate timeline report\n");
    printf("  correlate <case_name> <seconds>  - Correlate events within time window\n");
    printf("  help                             - Show this help\n");
}

int main(int argc, char* argv[]) {
    if(argc < 2) {
        print_usage();
        return 1;
    }
    
    if(strcmp(argv[1], "build") == 0 && argc >= 4) {
        TimelineBuilder builder;
        init_database(&builder, argv[2]);
        process_filesystem_timestamps(&builder, argv[3]);
        sqlite3_close(builder.db);
    }
    else if(strcmp(argv[1], "report") == 0 && argc >= 3) {
        TimelineBuilder builder;
        init_database(&builder, argv[2]);
        
        // Load events from database
        char* sql = "SELECT timestamp, source, event_type, description, artifact, user, host FROM timeline_events;";
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(builder.db, sql, -1, &stmt, 0);
        
        if(rc == SQLITE_OK) {
            while(sqlite3_step(stmt) == SQLITE_ROW) {
                TimelineEvent event;
                event.timestamp = sqlite3_column_int(stmt, 0);
                strcpy(event.source, (const char*)sqlite3_column_text(stmt, 1));
                strcpy(event.event_type, (const char*)sqlite3_column_text(stmt, 2));
                strcpy(event.description, (const char*)sqlite3_column_text(stmt, 3));
                strcpy(event.artifact, (const char*)sqlite3_column_text(stmt, 4));
                strcpy(event.user, (const char*)sqlite3_column_text(stmt, 5));
                strcpy(event.host, (const char*)sqlite3_column_text(stmt, 6));
                
                builder.events[builder.count] = event;
                builder.count++;
            }
            sqlite3_finalize(stmt);
        }
        
        const char* output_file = argc > 3 ? argv[3] : NULL;
        generate_timeline_report(&builder, output_file);
        sqlite3_close(builder.db);
    }
    else if(strcmp(argv[1], "correlate") == 0 && argc >= 4) {
        TimelineBuilder builder;
        init_database(&builder, argv[2]);
        int time_window = atoi(argv[3]);
        correlate_events(&builder, time_window);
        sqlite3_close(builder.db);
    }
    else if(strcmp(argv[1], "help") == 0) {
        print_usage();
    }
    else {
        printf("Unknown command: %s\n", argv[1]);
        print_usage();
        return 1;
    }
    
    return 0;
}
