#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_TEMPLATES 20
#define MAX_TEMPLATE_LENGTH 2048
#define MAX_VARIABLES 10
#define MAX_VAR_NAME 50
#define MAX_VAR_VALUE 100

typedef struct {
    char name[50];
    char subject[200];
    char body[1024];
    char variables[MAX_VARIABLES][MAX_VAR_NAME];
    int var_count;
    char difficulty[20];
} EmailTemplate;

typedef struct {
    char name[50];
    char body[256];
    char variables[MAX_VARIABLES][MAX_VAR_NAME];
    int var_count;
    char difficulty[20];
} SMSTemplate;

typedef struct {
    EmailTemplate email_templates[10];
    SMSTemplate sms_templates[10];
    int email_count;
    int sms_count;
} TemplateManager;

// Initialize template manager
void init_templates(TemplateManager* tm) {
    // Email templates
    strcpy(tm->email_templates[0].name, "urgent_password_reset");
    strcpy(tm->email_templates[0].subject, "Urgent: Password Reset Required");
    strcpy(tm->email_templates[0].body, 
        "Dear {name},\n\n"
        "Our security system detected unusual activity. Reset your password: {url}\n\n"
        "Best regards,\nIT Team\n{company}");
    strcpy(tm->email_templates[0].variables[0], "name");
    strcpy(tm->email_templates[0].variables[1], "url");
    strcpy(tm->email_templates[0].variables[2], "company");
    tm->email_templates[0].var_count = 3;
    strcpy(tm->email_templates[0].difficulty, "beginner");
    
    strcpy(tm->email_templates[1].name, "package_delivery");
    strcpy(tm->email_templates[1].subject, "Package Delivery Failed");
    strcpy(tm->email_templates[1].body,
        "Hello {name},\n\n"
        "Delivery failed for package {tracking}. Confirm: {url}\n\n"
        "Delivery Services");
    strcpy(tm->email_templates[1].variables[0], "name");
    strcpy(tm->email_templates[1].variables[1], "tracking");
    strcpy(tm->email_templates[1].variables[2], "url");
    tm->email_templates[1].var_count = 3;
    strcpy(tm->email_templates[1].difficulty, "intermediate");
    
    tm->email_count = 2;

    // SMS templates
    strcpy(tm->sms_templates[0].name, "bank_alert");
    strcpy(tm->sms_templates[0].body,
        "{bank} Alert: Suspicious activity. Reply YES to confirm.");
    strcpy(tm->sms_templates[0].variables[0], "bank");
    tm->sms_templates[0].var_count = 1;
    strcpy(tm->sms_templates[0].difficulty, "beginner");
    
    strcpy(tm->sms_templates[1].name, "package_sms");
    strcpy(tm->sms_templates[1].body,
        "UPS: Delivery failed. Confirm: {url}");
    strcpy(tm->sms_templates[1].variables[0], "url");
    tm->sms_templates[1].var_count = 1;
    strcpy(tm->sms_templates[1].difficulty, "intermediate");
    
    tm->sms_count = 2;
}

// Replace variables in template
void render_template(char* template, char* result, char vars[][2][MAX_VAR_VALUE], int var_count) {
    strcpy(result, template);
    
    for (int i = 0; i < var_count; i++) {
        char placeholder[60];
        snprintf(placeholder, sizeof(placeholder), "{%s}", vars[i][0]);
        
        char* pos = strstr(result, placeholder);
        while (pos != NULL) {
            // Calculate lengths
            size_t placeholder_len = strlen(placeholder);
            size_t value_len = strlen(vars[i][1]);
            size_t result_len = strlen(result);
            
            // Ensure we have enough space
            if (result_len - placeholder_len + value_len < MAX_TEMPLATE_LENGTH) {
                // Create new string with replacement
                char new_result[MAX_TEMPLATE_LENGTH];
                size_t prefix_len = pos - result;
                
                // Copy prefix
                strncpy(new_result, result, prefix_len);
                new_result[prefix_len] = '\0';
                
                // Add replacement value
                strcat(new_result, vars[i][1]);
                
                // Add suffix
                strcat(new_result, pos + placeholder_len);
                
                // Update result
                strcpy(result, new_result);
            }
            
            // Look for next occurrence
            pos = strstr(result, placeholder);
        }
    }
}

// Display available templates
void list_templates(TemplateManager* tm) {
    printf("EMAIL TEMPLATES:\n");
    for (int i = 0; i < tm->email_count; i++) {
        printf("%d. %s (%s)\n", i+1, tm->email_templates[i].name, 
               tm->email_templates[i].difficulty);
        printf("   Subject: %s\n", tm->email_templates[i].subject);
        printf("   Variables: ");
        for (int j = 0; j < tm->email_templates[i].var_count; j++) {
            printf("{%s} ", tm->email_templates[i].variables[j]);
        }
        printf("\n\n");
    }
    
    printf("SMS TEMPLATES:\n");
    for (int i = 0; i < tm->sms_count; i++) {
        printf("%d. %s (%s)\n", i+1, tm->sms_templates[i].name, 
               tm->sms_templates[i].difficulty);
        printf("   Body: %s\n", tm->sms_templates[i].body);
        printf("   Variables: ");
        for (int j = 0; j < tm->sms_templates[i].var_count; j++) {
            printf("{%s} ", tm->sms_templates[i].variables[j]);
        }
        printf("\n\n");
    }
}

// Simulate sending (educational purpose)
void simulate_send_email(char* to, char* subject, char* body) {
    printf("=== SIMULATED EMAIL SEND ===\n");
    printf("To: %s\n", to);
    printf("Subject: %s\n", subject);
    printf("Body:\n%s\n", body);
    printf("============================\n\n");
}

void simulate_send_sms(char* to, char* body) {
    printf("=== SIMULATED SMS SEND ===\n");
    printf("To: %s\n", to);
    printf("Body: %s\n", body);
    printf("==========================\n\n");
}

int main() {
    printf("Social Engineering Toolkit - C Implementation\n");
    printf("FOR EDUCATIONAL PURPOSES ONLY\n\n");
    
    TemplateManager tm;
    init_templates(&tm);
    
    int choice;
    do {
        printf("1. List Templates\n");
        printf("2. Send Test Email\n");
        printf("3. Send Test SMS\n");
        printf("4. Exit\n");
        printf("Choice: ");
        scanf("%d", &choice);
        getchar(); // Clear newline
        
        switch (choice) {
            case 1:
                list_templates(&tm);
                break;
                
            case 2: {
                // Send test email
                int template_choice;
                printf("Select email template (1-%d): ", tm.email_count);
                scanf("%d", &template_choice);
                getchar();
                
                if (template_choice < 1 || template_choice > tm.email_count) {
                    printf("Invalid choice\n");
                    break;
                }
                
                EmailTemplate* template = &tm.email_templates[template_choice - 1];
                
                // Get variable values
                char vars[MAX_VARIABLES][2][MAX_VAR_VALUE];
                for (int i = 0; i < template->var_count; i++) {
                    printf("Enter value for {%s}: ", template->variables[i]);
                    fgets(vars[i][1], MAX_VAR_VALUE, stdin);
                    vars[i][1][strcspn(vars[i][1], "\n")] = 0; // Remove newline
                    strcpy(vars[i][0], template->variables[i]);
                }
                
                // Render template
                char subject[200];
                char body[1024];
                render_template(template->subject, subject, vars, template->var_count);
                render_template(template->body, body, vars, template->var_count);
                
                // Simulate send
                char to[100];
                printf("Enter recipient email: ");
                fgets(to, sizeof(to), stdin);
                to[strcspn(to, "\n")] = 0;
                
                simulate_send_email(to, subject, body);
                break;
            }
                
            case 3: {
                // Send test SMS
                int template_choice;
                printf("Select SMS template (1-%d): ", tm.sms_count);
                scanf("%d", &template_choice);
                getchar();
                
                if (template_choice < 1 || template_choice > tm.sms_count) {
                    printf("Invalid choice\n");
                    break;
                }
                
                SMSTemplate* template = &tm.sms_templates[template_choice - 1];
                
                // Get variable values
                char vars[MAX_VARIABLES][2][MAX_VAR_VALUE];
                for (int i = 0; i < template->var_count; i++) {
                    printf("Enter value for {%s}: ", template->variables[i]);
                    fgets(vars[i][1], MAX_VAR_VALUE, stdin);
                    vars[i][1][strcspn(vars[i][1], "\n")] = 0;
                    strcpy(vars[i][0], template->variables[i]);
                }
                
                // Render template
                char body[256];
                render_template(template->body, body, vars, template->var_count);
                
                // Simulate send
                char to[20];
                printf("Enter recipient phone: ");
                fgets(to, sizeof(to), stdin);
                to[strcspn(to, "\n")] = 0;
                
                simulate_send_sms(to, body);
                break;
            }
                
            case 4:
                printf("Exiting...\n");
                break;
                
            default:
                printf("Invalid choice\n");
        }
        
    } while (choice != 4);
    
    return 0;
}
