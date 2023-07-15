#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(108714);
 script_version("1.6");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/28");

 script_name(english:"PCI DSS Compliance : Scan Interference");
 script_summary(english:"Network interference did not allow scan to fulfill PCI DSS scan validation requirements.");

 script_set_attribute(attribute:"synopsis", value:"Previously open ports are now closed or filtered.");
 script_set_attribute(attribute:"description", value:
"Interference from either the network or the host did not allow the 
scan to fulfill the PCI DSS scan validation requirements. This 
report is insufficient to certify this server. There may be a 
firewall, IDS or other software blocking Nessus from scanning.");
 script_set_attribute(attribute:"solution", value:
"  - Adjust Nessus scan settings to improve performance.
  - Whitelist the Nessus scanner for any IDS or Firewall which
    may be blocking the scan.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"Score from an in depth analysis done by Tenable");
 
 script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/29");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 script_category(ACT_END);
 script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"General");

 script_dependencies("find_service1.nasl","ssl_supported_ciphers.nasl");
 script_require_keys("Settings/PCI_DSS");
 script_exclude_keys("Host/dead", "Settings/PCI_DSS_local_checks");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

if (get_kb_item("Host/dead")) exit(0, "The remote host was not responding.");

if (!get_kb_item("Settings/PCI_DSS"))
  audit(AUDIT_PCI);

if (get_kb_item("Settings/PCI_DSS_local_checks"))
  exit(1, "This plugin only runs for PCI External scans.");

ports = get_kb_list("Ports/tcp/*");
if (isnull(ports)) exit(0, "No TCP ports were found to be open.");

number_of_ports = 0;
changed_ports = 0;
wrapped_ports = 0;
filtered_ports = 0;
ssl_ports = 0;

read_timeout = get_read_timeout();
timeout = 2 * read_timeout;

#
# Do not do a false positive if netstat or the snmp
# port scanners have been used.
#
if(!isnull(ports) && !get_kb_item("Host/scanners/netstat") && !get_kb_item("Host/scanners/snmp_scanner"))
{
  # Gather list of starttls ports, we will use ENCAPS_IP transport
  # for them, rather than the SSL/TLS they might be marked as.
  var starttls_ports = [];

  foreach var key (keys(get_kb_list('*/starttls')))
  {
    var pieces = split(key, sep:'/', keep:FALSE);

    # KB are of form '<something-something>/<port>/starttls'
    if (empty_or_null(pieces[len(pieces) - 2]))
      continue;

    var potential_port = pieces[len(pieces) - 2];

    if (potential_port =~ "^[0-9]+$")
      starttls_ports = make_list(starttls_ports, potential_port);
  }


  tcp_report = "The following ports were initially detected as open but are now closed or unresponsive:";
  ## Detect ports which were open but are now closed/unresponsive.
  foreach port (keys(ports))
  {
     number_of_ports ++;
     port = int(port - "Ports/tcp/");

     # Only check syn-synack-ack on starttls ports
     var use_clear_text_encaps_on_starttls_port = FALSE;

     foreach var starttls_port (starttls_ports)
     {
       if (starttls_port != port) continue;

       use_clear_text_encaps_on_starttls_port = TRUE;
       break;
     }

     if (use_clear_text_encaps_on_starttls_port)
       sock = open_sock_tcp(port, timeout: timeout, transport:ENCAPS_IP);
     else
       sock = open_sock_tcp(port, timeout: timeout);

     if (!sock)
     {
        tcp_report += '\n  - ' + string(port);
        changed_ports++;
     }
     else close(sock);
  }
}

## Check for 'tcpwrapped' ports
wrapped = get_kb_list("Services/wrapped");
wrapped_report = "Services could not be identified on the following ports. They closed the connection without sending any data:";
if(!isnull(wrapped))
{
  foreach wport (wrapped)
  {
      wrapped_report += '\n  - ' + string(wport);
      wrapped_ports++;
  }
}

# Filtered services
filtered = get_kb_list("Services/filtered");
filtered_report = "Services could not be identified on the following ports. The response appears to have been filtered:";
if(!isnull(filtered))
{
  foreach fport (filtered)
  {
    filtered_report += '\n  - ' + string(fport);
    filtered_ports++;
  }
}

# Seen sometimes with `openssl s_server`, which can only service one connection
# at a time. Any other services like this will cause ssl_supported_ciphers.nasl
# to give up early, which means we might miss weak ciphers.
ssl = get_kb_list("scan_interference/ssl_supported_ciphers");
ssl_report = "Some services timed out or refused to connect while testing supported SSL ciphers:";
if(!isnull(ssl))
{
  foreach sport (ssl)
  {
    ssl_report += '\n  - ' + string(sport);
    ssl_ports++;
  }
}

report = "";
if (changed_ports > 0) report += tcp_report + '\n\n';
if (wrapped_ports > 0) report += wrapped_report + '\n\n';
if (filtered_ports > 0) report += filtered_report + '\n\n';
if (ssl_ports > 0) report += ssl_report + '\n\n';

if (changed_ports > 0 || wrapped_ports > 0 || filtered_ports > 0 || ssl_ports > 0)
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
else 
  exit(0, "No previously open ports were found to be closed or unresponsive.");
