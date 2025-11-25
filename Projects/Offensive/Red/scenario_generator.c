/**
 * Red/Blue Exercise Scenarios Generator - C Implementation
 * Compile: gcc -o scenario_generator scenario_generator.c -lm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#define MAX_OBJECTIVES 10
#define MAX_TECHNIQUES 20
#define MAX_ACTIONS 15
#define MAX_ASSETS 20
#define MAX_IOCS 10
#define MAX_COUNTERMEASURES 8

typedef struct {
    char id[20];
    char name[100];
    char description[500];
    char difficulty[20];
    char mitre_attack_id[20];
    char detection_difficulty[20];
    char iocs[MAX_IOCS][100];
    int ioc_count;
    char countermeasures[MAX_COUNTERMEASURES][100];
    int countermeasure_count;
} AttackTechnique;

typedef struct {
    char name[100];
    char description[500];
    int points;
    char category[50];
} ScenarioObjective;

typedef struct {
    char name[100];
    char description[500];
    char effectiveness[20];
    char tools[200];
    char time_required[50];
} BlueTeamAction;

typedef struct {
    char type[50];
    int count;
    char os[50];
} InfrastructureAsset;

typedef struct {
    char name[200];
    char description[500];
    char difficulty[20];
    char duration[50];
    ScenarioObjective red_team_objectives[MAX_OBJECTIVES];
    int red_obj_count;
    ScenarioObjective blue_team_objectives[MAX_OBJECTIVES];
    int blue_obj_count;
    AttackTechnique attack_techniques[MAX_TECHNIQUES];
    int tech_count;
    BlueTeamAction blue_team_actions[MAX_ACTIONS];
    int action_count;
    InfrastructureAsset assets[MAX_ASSETS];
    int asset_count;
    int user_count;
    char departments[5][50];
    int dept_count;
} ExerciseScenario;

// Predefined attack techniques
AttackTechnique techniques[] = {
    {
        "T1566.001",
        "Phishing - Spearphishing Attachment",
        "Send targeted emails with malicious attachments",
        "Medium",
        "T1566.001",
        "Medium",
        {
            "Unusual email attachments",
            "Suspicious sender domains",
            "Macro-enabled documents",
            "Unusual process spawning"
        },
        4,
        {
            "Email filtering for executables",
            "User awareness training",
            "Endpoint detection for macros",
            "Network monitoring for C2"
        },
        4
    },
    {
        "T1059.003", 
        "Command and Scripting Interpreter - Windows Command Shell",
        "Use cmd.exe for command execution",
        "Low",
        "T1059.003",
        "Easy",
        {
            "Suspicious command-line arguments",
            "Unusual parent-child processes",
            "Commands from unusual locations"
        },
        3,
        {
            "Process monitoring",
            "Application whitelisting",
            "Command-line auditing"
        },
        3
    },
    {
        "T1134",
        "Access Token Manipulation", 
        "Manipulate access tokens to escalate privileges",
        "High",
        "T1134",
        "Hard",
        {
            "Token manipulation API calls",
            "Unusual process integrity levels",
            "Privilege escalation attempts"
        },
        3,
        {
            "Privileged account management",
            "Token filtering",
            "Process integrity monitoring"
        },
        3
    }
};

int technique_count = sizeof(techniques) / sizeof(techniques[0]);

// Scenario templates
typedef struct {
    char name[100];
    char description[500];
    char difficulty[20];
    char duration[50];
    char red_focus[3][50];
    char blue_focus[3][50];
} ScenarioTemplate;

ScenarioTemplate templates[] = {
    {
        "Advanced Persistent Threat Simulation",
        "Simulate sophisticated nation-state actor",
        "High",
        "2 weeks",
        {"Persistence", "Lateral Movement", "Data Exfiltration"},
        {"Threat Hunting", "Incident Response", "Forensics"}
    },
    {
        "Ransomware Attack Scenario",
        "Simulate ransomware deployment and impact", 
        "Medium",
        "3 days",
        {"Initial Access", "Execution", "Impact"},
        {"Containment", "Recovery", "Business Continuity"}
    }
};

int template_count = sizeof(templates) / sizeof(templates[0]);

// Infrastructure templates
typedef struct {
    char type[50];
    char description[200];
    InfrastructureAsset assets[MAX_ASSETS];
    int asset_count;
    int user_count;
    char departments[5][50];
    int dept_count;
} InfrastructureTemplate;

InfrastructureTemplate infrastructures[] = {
    {
        "corporate_network",
        "Standard corporate network environment",
        {
            {"Domain Controller", 2, "Windows Server 2019"},
            {"File Server", 1, "Windows Server 2019"},
            {"Web Server", 2, "Linux Ubuntu"},
            {"Workstation", 20, "Windows 10"},
            {"Network Firewall", 1, ""},
            {"IDS/IPS", 1, ""},
            {"SIEM", 1, ""}
        },
        7,
        50,
        {"HR", "Finance", "IT", "Marketing", "Operations"},
        5
    },
    {
        "cloud_environment",
        "Cloud-native environment",
        {
            {"EC2 Instances", 10, "Linux/Windows"},
            {"S3 Buckets", 5, ""},
            {"RDS Databases", 2, ""},
            {"Load Balancer", 1, ""},
            {"CloudTrail", 1, ""}
        },
        5,
        100,
        {"Development", "Operations", "Security"},
        3
    }
};

int infra_count = sizeof(infrastructures) / sizeof(infrastructures[0]);

void generate_red_objectives(const char* focus_areas[], int focus_count, ScenarioObjective objectives[], int* obj_count) {
    *obj_count = 0;
    
    for(int i = 0; i < focus_count && *obj_count < MAX_OBJECTIVES; i++) {
        if(strcmp(focus_areas[i], "Persistence") == 0) {
            strcpy(objectives[*obj_count].name, "Establish Persistence");
            strcpy(objectives[*obj_count].description, "Create multiple persistence mechanisms");
            objectives[*obj_count].points = 35;
            strcpy(objectives[*obj_count].category, "Persistence");
            (*obj_count)++;
        } else if(strcmp(focus_areas[i], "Lateral Movement") == 0) {
            strcpy(objectives[*obj_count].name, "Domain Compromise");
            strcpy(objectives[*obj_count].description, "Compromise domain administrator account");
            objectives[*obj_count].points = 50;
            strcpy(objectives[*obj_count].category, "Lateral Movement");
            (*obj_count)++;
        } else if(strcmp(focus_areas[i], "Initial Access") == 0) {
            strcpy(objectives[*obj_count].name, "Gain Initial Foothold");
            strcpy(objectives[*obj_count].description, "Establish initial access to target environment");
            objectives[*obj_count].points = 25;
            strcpy(objectives[*obj_count].category, "Initial Access");
            (*obj_count)++;
        }
    }
}

void generate_blue_objectives(const char* focus_areas[], int focus_count, ScenarioObjective objectives[], int* obj_count) {
    *obj_count = 0;
    
    for(int i = 0; i < focus_count && *obj_count < MAX_OBJECTIVES; i++) {
        if(strcmp(focus_areas[i], "Threat Hunting") == 0) {
            strcpy(objectives[*obj_count].name, "IOC Identification");
            strcpy(objectives[*obj_count].description, "Identify multiple IOCs from attack");
            objectives[*obj_count].points = 30;
            strcpy(objectives[*obj_count].category, "Threat Hunting");
            (*obj_count)++;
        } else if(strcmp(focus_areas[i], "Incident Response") == 0) {
            strcpy(objectives[*obj_count].name, "Containment");
            strcpy(objectives[*obj_count].description, "Contain the incident within 2 hours");
            objectives[*obj_count].points = 35;
            strcpy(objectives[*obj_count].category, "Incident Response");
            (*obj_count)++;
        }
    }
}

void select_techniques(const char* difficulty, AttackTechnique selected_techs[], int* tech_count) {
    *tech_count = 0;
    
    for(int i = 0; i < technique_count && *tech_count < MAX_TECHNIQUES; i++) {
        if(strcmp(difficulty, "Low") == 0 && strcmp(techniques[i].difficulty, "Low") == 0) {
            selected_techs[*tech_count] = techniques[i];
            (*tech_count)++;
        } else if(strcmp(difficulty, "Medium") == 0 && 
                 (strcmp(techniques[i].difficulty, "Low") == 0 || 
                  strcmp(techniques[i].difficulty, "Medium") == 0)) {
            selected_techs[*tech_count] = techniques[i];
            (*tech_count)++;
        } else if(strcmp(difficulty, "High") == 0) {
            selected_techs[*tech_count] = techniques[i];
            (*tech_count)++;
        }
    }
}

void generate_blue_actions(AttackTechnique techs[], int tech_count, BlueTeamAction actions[], int* action_count) {
    *action_count = 0;
    
    for(int i = 0; i < tech_count && *action_count < MAX_ACTIONS; i++) {
        for(int j = 0; j < techs[i].countermeasure_count && *action_count < MAX_ACTIONS; j++) {
            snprintf(actions[*action_count].name, sizeof(actions[*action_count].name), 
                    "Defend against %s", techs[i].name);
            snprintf(actions[*action_count].description, sizeof(actions[*action_count].description),
                    "Implement %s", techs[i].countermeasures[j]);
            strcpy(actions[*action_count].effectiveness, "High");
            strcpy(actions[*action_count].tools, "SIEM, EDR, Network Monitoring");
            strcpy(actions[*action_count].time_required, "1-2 hours");
            (*action_count)++;
        }
    }
}

void generate_scenario(const char* scenario_type, const char* infrastructure_type, 
                      const char* difficulty, ExerciseScenario* scenario) {
    // Find template
    ScenarioTemplate* template = NULL;
    for(int i = 0; i < template_count; i++) {
        if(strstr(templates[i].name, scenario_type) != NULL) {
            template = &templates[i];
            break;
        }
    }
    if(!template) template = &templates[0];
    
    // Find infrastructure
    InfrastructureTemplate* infra = NULL;
    for(int i = 0; i < infra_count; i++) {
        if(strcmp(infrastructures[i].type, infrastructure_type) == 0) {
            infra = &infrastructures[i];
            break;
        }
    }
    if(!infra) infra = &infrastructures[0];
    
    // Set basic scenario info
    snprintf(scenario->name, sizeof(scenario->name), "%s - %s", template->name, infra->description);
    strcpy(scenario->description, template->description);
    strcpy(scenario->difficulty, difficulty);
    strcpy(scenario->duration, template->duration);
    
    // Generate objectives
    generate_red_objectives(template->red_focus, 3, scenario->red_team_objectives, &scenario->red_obj_count);
    generate_blue_objectives(template->blue_focus, 3, scenario->blue_team_objectives, &scenario->blue_obj_count);
    
    // Select techniques
    select_techniques(difficulty, scenario->attack_techniques, &scenario->tech_count);
    
    // Generate blue team actions
    generate_blue_actions(scenario->attack_techniques, scenario->tech_count, 
                         scenario->blue_team_actions, &scenario->action_count);
    
    // Copy infrastructure
    scenario->asset_count = infra->asset_count;
    for(int i = 0; i < infra->asset_count; i++) {
        scenario->assets[i] = infra->assets[i];
    }
    scenario->user_count = infra->user_count;
    scenario->dept_count = infra->dept_count;
    for(int i = 0; i < infra->dept_count; i++) {
        strcpy(scenario->departments[i], infra->departments[i]);
    }
}

void print_scenario_json(const ExerciseScenario* scenario) {
    printf("{\n");
    printf("  \"name\": \"%s\",\n", scenario->name);
    printf("  \"description\": \"%s\",\n", scenario->description);
    printf("  \"difficulty\": \"%s\",\n", scenario->difficulty);
    printf("  \"duration\": \"%s\",\n", scenario->duration);
    
    printf("  \"red_team_objectives\": [\n");
    for(int i = 0; i < scenario->red_obj_count; i++) {
        printf("    {\n");
        printf("      \"name\": \"%s\",\n", scenario->red_team_objectives[i].name);
        printf("      \"description\": \"%s\",\n", scenario->red_team_objectives[i].description);
        printf("      \"points\": %d,\n", scenario->red_team_objectives[i].points);
        printf("      \"category\": \"%s\"\n", scenario->red_team_objectives[i].category);
        printf("    }%s\n", i < scenario->red_obj_count - 1 ? "," : "");
    }
    printf("  ],\n");
    
    printf("  \"infrastructure\": {\n");
    printf("    \"assets\": [\n");
    for(int i = 0; i < scenario->asset_count; i++) {
        printf("      {\n");
        printf("        \"type\": \"%s\",\n", scenario->assets[i].type);
        printf("        \"count\": %d,\n", scenario->assets[i].count);
        printf("        \"os\": \"%s\"\n", scenario->assets[i].os);
        printf("      }%s\n", i < scenario->asset_count - 1 ? "," : "");
    }
    printf("    ],\n");
    printf("    \"users\": %d\n", scenario->user_count);
    printf("  }\n");
    printf("}\n");
}

void print_scenario_text(const ExerciseScenario* scenario) {
    printf("=== RED/BLUE EXERCISE SCENARIO ===\n\n");
    printf("Name: %s\n", scenario->name);
    printf("Description: %s\n", scenario->description);
    printf("Difficulty: %s\n", scenario->difficulty);
    printf("Duration: %s\n\n", scenario->duration);
    
    printf("RED TEAM OBJECTIVES:\n");
    for(int i = 0; i < scenario->red_obj_count; i++) {
        printf("  %d. %s (%d points)\n", i+1, scenario->red_team_objectives[i].name, 
               scenario->red_team_objectives[i].points);
        printf("     %s\n", scenario->red_team_objectives[i].description);
    }
    
    printf("\nBLUE TEAM OBJECTIVES:\n");
    for(int i = 0; i < scenario->blue_obj_count; i++) {
        printf("  %d. %s (%d points)\n", i+1, scenario->blue_team_objectives[i].name,
               scenario->blue_team_objectives[i].points);
        printf("     %s\n", scenario->blue_team_objectives[i].description);
    }
    
    printf("\nINFRASTRUCTURE:\n");
    for(int i = 0; i < scenario->asset_count; i++) {
        printf("  - %s: %d", scenario->assets[i].type, scenario->assets[i].count);
        if(strlen(scenario->assets[i].os) > 0) {
            printf(" (%s)", scenario->assets[i].os);
        }
        printf("\n");
    }
    printf("  Total Users: %d\n", scenario->user_count);
}

int main(int argc, char* argv[]) {
    char* scenario_type = "apt_simulation";
    char* infrastructure = "corporate_network";
    char* difficulty = "Medium";
    char* format = "text";
    
    // Simple argument parsing
    for(int i = 1; i < argc; i++) {
        if(strcmp(argv[i], "--scenario-type") == 0 && i+1 < argc) {
            scenario_type = argv[++i];
        } else if(strcmp(argv[i], "--infrastructure") == 0 && i+1 < argc) {
            infrastructure = argv[++i];
        } else if(strcmp(argv[i], "--difficulty") == 0 && i+1 < argc) {
            difficulty = argv[++i];
        } else if(strcmp(argv[i], "--format") == 0 && i+1 < argc) {
            format = argv[++i];
        }
    }
    
    srand(time(NULL));
    
    ExerciseScenario scenario;
    generate_scenario(scenario_type, infrastructure, difficulty, &scenario);
    
    if(strcmp(format, "json") == 0) {
        print_scenario_json(&scenario);
    } else {
        print_scenario_text(&scenario);
    }
    
    return 0;
}
