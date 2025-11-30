# DLP Zeek Scripts - Lab Use Only
# Data exfiltration detection heuristics

@load base/protocols/http
@load base/protocols/dns
@load base/protocols/ssl
@load base/protocols/ftp
@load base/protocols/smtp

module DLP;

export {
    # DLP notice types
    redef enum Notice::Type += {
        LargeHTTPPost,
        DNS_Tunneling_Suspected,
        Suspicious_TLS_Connection,
        FTP_File_Upload,
        SMTP_External_Attachment,
        Beaconing_Behavior,
        High_Entropy_DNS
    };

    # Configuration
    const allowed_domains: set[string] = {
        "google.com", "microsoft.com", "apple.com", 
        "example.com", "company.com"
    } &redef;

    const large_post_threshold: count = 1000000 &redef; # 1MB
    const dns_query_length_threshold: count = 100 &redef;
    const dns_txt_threshold: count = 10 &redef; # TXT queries per minute
}

# Track DNS TXT queries for tunneling detection
global dns_txt_queries: table[addr] of count &default=0 &write_expire=1min;

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
{
    if ( is_orig && c$http$method == "POST" && stat$body_length > large_post_threshold ) {
        local host = c$http$host;
        
        # Check if domain is in allowed list
        if ( host !in allowed_domains ) {
            NOTICE([$note=LargeHTTPPost,
                    $conn=c,
                    $msg=fmt("Large HTTP POST to unknown domain: %s, size: %d", host, stat$body_length),
                    $identifier=cat(c$id$orig_h)]);
        }
    }
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    # Check for long DNS queries (potential tunneling)
    if ( |query| > dns_query_length_threshold ) {
        NOTICE([$note=High_Entropy_DNS,
                $conn=c,
                $msg=fmt("Long DNS query: %s (%d chars)", query, |query|),
                $identifier=cat(c$id$orig_h)]);
    }

    # Track TXT record queries
    if ( qtype == 16 ) {  # TXT record
        dns_txt_queries[c$id$orig_h] += 1;
        
        if ( dns_txt_queries[c$id$orig_h] >= dns_txt_threshold ) {
            NOTICE([$note=DNS_Tunneling_Suspected,
                    $conn=c,
                    $msg=fmt("High volume of DNS TXT queries: %d in 1min", dns_txt_queries[c$id$orig_h]),
                    $identifier=cat(c$id$orig_h)]);
        }
    }
}

event ftp_request(c: connection, command: string, arg: string)
{
    # Detect file uploads
    if ( command == "STOR" || command == "STOU" ) {
        NOTICE([$note=FTP_File_Upload,
                $conn=c,
                $msg=fmt("FTP file upload: %s", arg),
                $identifier=cat(c$id$orig_h)]);
    }
}

event smtp_request(c: connection, command: string, arg: string)
{
    # Detect mail from external domains with attachments
    if ( command == "MAIL" && /^FROM:/ in arg ) {
        local from_addr = sub(arg, /^FROM:/, "");
        from_addr = gsub(from_addr, /[<>]/, "");
        
        # Extract domain
        local parts = split_string(from_addr, /@/);
        if ( |parts| == 2 ) {
            local domain = parts[1];
            
            # Check if domain is external
            if ( domain !in allowed_domains ) {
                # Note: Attachment detection would require deeper SMTP analysis
                NOTICE([$note=SMTP_External_Attachment,
                        $conn=c,
                        $msg=fmt("SMTP from external domain: %s", domain),
                        $identifier=cat(c$id$orig_h)]);
            }
        }
    }
}

event ssl_established(c: connection)
{
    # Check for TLS connections to unknown domains
    if ( c$ssl?$server_name && c$ssl$server_name !in allowed_domains ) {
        NOTICE([$note=Suspicious_TLS_Connection,
                $conn=c,
                $msg=fmt("TLS connection to unknown domain: %s", c$ssl$server_name),
                $identifier=cat(c$id$orig_h)]);
    }
}

# Beaconing detection - track periodic connections
global host_connections: table[addr] of vector of time &write_expire=1hour;

event connection_established(c: connection)
{
    local orig = c$id$orig_h;
    
    if ( orig !in host_connections ) {
        host_connections[orig] = vector();
    }
    
    host_connections[orig][|host_connections[orig]|] = network_time();
    
    # Check for periodic connections (simple version)
    if ( |host_connections[orig]| >= 5 ) {
        local intervals: vector of interval;
        for ( i in 1..|host_connections[orig]|-1 ) {
            intervals[i] = host_connections[orig][i] - host_connections[orig][i-1];
        }
        
        # Simple periodicity check (std dev of intervals)
        local mean: double = 0.0;
        for ( i in intervals ) {
            mean += i;
        }
        mean = mean / |intervals|;
        
        local variance: double = 0.0;
        for ( i in intervals ) {
            variance += (i - mean) * (i - mean);
        }
        variance = variance / |intervals|;
        
        # Low variance suggests periodic behavior
        if ( variance < 1.0 ) {
            NOTICE([$note=Beaconing_Behavior,
                    $conn=c,
                    $msg=fmt("Potential beaconing behavior from %s (variance: %.2f)", orig, variance),
                    $identifier=cat(orig)]);
        }
    }
}
