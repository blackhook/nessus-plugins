#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108659);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/16");

  script_name(english:"SMTP Host Information in NTLM SSP");
  script_summary(english:"Parses host information out of NTLM SSP message, if available.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus can obtain information about the host by examining the NTLM SSP
message."
  );
  script_set_attribute(attribute:"description", value:
"Nessus can obtain information about the host by examining the NTLM SSP
challenge issued during NTLM authentication, over STMP."
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  
  script_dependencies("smtpserver_detect.nasl", 
                      "smtp_authentication.nasl");
  script_require_ports("Services/smtp", 25);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");
include("audit.inc");
include("byte_func.inc");
include("lists.inc");
include("ntlmssp.inc");


var auth_methods, auth_tls_methods;
var port;
var ntlm_blob;
var use_tls, ntlm_flags;
var resp, resp_blob;
var transport;
var skt;
var parser;

function check_protocol_errors ()
{
  var resp = _FCT_ANON_ARGS[0];
  if (!strlen(resp)) 
    exit(1, "The SMTP server did not send back a valid response.");
  return NULL;
}


port = get_kb_item("Services/smtp");
if (isnull(port)) port = 25;

transport = get_kb_item("Transports/TCP/"+port);

auth_methods = get_kb_list("smtp/"+port+"/auth");
auth_tls_methods = get_kb_list("smtp/"+port+"/auth_tls");

if (!isnull(auth_tls_methods) && collib::contains(make_list(auth_tls_methods), 'NTLM'))
{
  use_tls = TRUE;
} else {
  use_tls = FALSE;
  if (isnull(auth_methods) || !collib::contains(make_list(auth_methods), 'NTLM'))
  {
    audit(AUDIT_HOST_NOT, "affected");
  }
}

ntlm_flags = mkword(order:BYTE_ORDER_LITTLE_ENDIAN,
                    0x00000001 | # negotiate unicode
                    0x00000002 | # negotiate OEM strings
                    0x00000004 | # request target
                    0x00000200 | # negotiate NTLM
                    0x00008000 | # negotiate Always Sign
                    0x20000000 | # negotiate NTLM2 Key
                    0x80000000   # negotiate 56
);
ntlm_auth_blob = base64(str: 'NTLMSSP\x00'                      # 8 bytes (identifier)
                           + '\x01\x00\x00\x00'                 # 4 bytes (NTLMSSP_NEGOTIATE)
                           + ntlm_flags                         # 4 bytes (defined above)
                           + '\x00\x00\x00\x00\x00\x00\x00\x00' # 8 bytes (workstation domain)
                           + '\x00\x00\x00\x00\x00\x00\x00\x00' # 8 bytes (workstation name)
);

# Connect to the SMTP service, and send EHLO
skt = smtp_open(port:port,
                ehlo:get_host_name(),
                exit_on_fail:TRUE);

if (use_tls)
{
  var tmp_skt;
  tmp_skt = smtp_starttls(socket:skt,
                          dont_read_banner:TRUE,  # we don't need another HELO
                          encaps:ENCAPS_TLSv1,    # we don't need to know the way home
                          exit_on_fail:TRUE); 
  if (tmp_skt && tmp_skt != skt)
  {
    close(skt);
    skt = tmp_skt;
  }
}

smtp_send_raw(socket:skt, data:'AUTH NTLM\r\n');
resp = smtp_recv_line(socket:skt, code:334); 
check_protocol_errors(resp);
smtp_send_raw(socket:skt, data:ntlm_auth_blob+'\r\n');
resp = smtp_recv_line(socket:skt, code:334);
check_protocol_errors(resp);
smtp_close(socket:skt);

resp = chomp(substr(resp, 4));

set_kb_item(name:"smtp/"+port+"/ntlm/challenge", value:resp);

resp_blob = base64_decode(str:resp);

parser = new("ntlm_parser", resp_blob);
parser.parse();

# Now, build the report. 
report = 'Nessus was able to obtain the following information about the host, by \n'
       + 'parsing the SMTP server\'s NTLM SSP message:\n'
       + '\n\tTarget Name:           '+parser.get('target_realm')
       + '\n\tNetBIOS Domain Name:   '+parser.get('netbios_domain_name')
       + '\n\tNetBIOS Computer Name: '+parser.get('netbios_computer_name')
       + '\n\tDNS Domain Name:       '+parser.get('dns_domain_name')
       + '\n\tDNS Computer Name:     '+parser.get('dns_computer_name')
       + '\n\tDNS Tree Name:         '+parser.get('dns_tree_name')
       + '\n\tProduct Version:       '+parser.get('os_version') + '\n';

# set kb items, for future use
foreach (field in ["netbios_domain_name",
                   "netbios_computer_name",
                   "dns_domain_name",
                   "dns_computer_name",
                   "dns_tree_name",
                   "os_version",
                   "target_realm"])
{
  set_kb_item(name:"smtp/"+port+"/ntlm/host/"+field, value:parser.get(field));
}

security_note(port:  port,
              extra: report);




