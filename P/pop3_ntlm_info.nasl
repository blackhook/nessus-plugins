#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(108806);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

  script_name(english:"POP3 Host Information in NTLM SSP");
  script_summary(english:"Parses host information out of NTLM SSP message, if available");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Nessus can obtain information about the host by examining the NTLM SSP message."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Nessus can obtain information about the host by examining the NTLM
SSP challenge issued during the NTLM authentication, over POP3
protocol."
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/03");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2020 Tenable Network Security, Inc.");

  script_dependencies("pop3_starttls.nasl");
  script_require_ports("Services/pop3", 110);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("pop3_func.inc");
include("ntlmssp.inc");
include("kerberos_func.inc");
include("smb_func.inc");
include("audit.inc");

function encode_ntlm()
{
  local_var ntlm_auth_blob, ntlm_flags;

  ntlm_flags = mkword(order:BYTE_ORDER_LITTLE_ENDIAN,
                    0x00000001 | # negotiate unicode
                    0x00000002 | # negotiate OEM strings
                    0x00000004 | # request target
                    0x00000200 | # negotiate NTLM
                    0x00008000 | # negotiate Always Sign
                    0x20000000 | # negotiate NTLM2 Key
                    0x80000000   # negotiate 56
  );
  ntlm_auth_blob = base64(str:'NTLMSSP\x00'                    # 8 bytes (identifier)
                          + '\x01\x00\x00\x00'                 # 4 bytes (NTLMSSP_NEGOTIATE)
                          + ntlm_flags                         # 4 bytes (defined above)
                          + '\x00\x00\x00\x00\x00\x00\x00\x00' # 8 bytes (workstation domain)
                          + '\x00\x00\x00\x00\x00\x00\x00\x00' # 8 bytes (workstation name)
  );

  return ntlm_auth_blob;
}

protocol = "POP3";
port = get_service(svc:"pop3", default:110, exit_on_fail:TRUE);

banner = open_pop3_connect (port:port);

if (empty_or_null(banner) || empty_or_null(banner['soc']) || empty_or_null(banner['banner'])) audit(AUDIT_SOCK_FAIL, port, protocol);

soc = banner['soc'];
banner = pregmatch(pattern:"(\+OK) *(.*)", string:banner['banner'], icase:TRUE);

if (!empty_or_null(banner[2])) banner = banner[2];

startmatch = pregmatch(pattern:"(.*) ([0-9]*) POP3 server version ([0-9.]*) \((.*)\) ready.", string:banner, icase:TRUE);

# Send to upgrade to SSL Connection if Operator supports the option
if (empty_or_null(get_kb_item("global_settings/disable_test_ssl_based_services")))
{
  resp = pop3_send_cmd( socket:soc, cmd:'STLS');

  if (empty_or_null(resp))
  {
    close(soc);
    audit(AUDIT_RESP_NOT, port, "STLS", protocol);
  }

  if (toupper(resp['cond']) == '+OK')
  {
    # nb: finally, we need to make sure the second command worked.
    soc = socket_negotiate_ssl(socket:soc, transport:ENCAPS_TLSv1);
    if (!soc)
    {
      close(soc);
      audit(AUDIT_SSL_FAIL, protocol, port);
    }
  }
}

# Check if we can see the support Authentication methods.
resp = pop3_send_cmd(socket:soc, cmd:'AUTH');

if (empty_or_null(resp) || empty_or_null(resp['text']))
{
  close(soc);
  audit(AUDIT_RESP_NOT, port, "AUTH", protocol);
}

auth_methods = NULL;

if (resp['text'] =~ "^\+OK.*")
{
  auth_resp = split(resp['text'], sep:'\r\n', keep:FALSE);

  start = 1;
  end = len(auth_resp) - 1;

  if (start < end)
  {
    for(index = start; index < end; index++)
    {
      auth_methods = auth_resp[index] + ' ' + auth_methods;
    }
    auth_methods = auth_methods + ' ' + auth_resp[index];
  }
}

resp = pop3_send_cmd(socket:soc, cmd:'AUTH NTLM');

if (empty_or_null(resp) || empty_or_null(resp['text']) || resp['text'] =~ "-ERR.*")
{
  close(soc);
  audit(AUDIT_RESP_NOT, port, "AUTH NTLM", protocol);
}

msg3 = encode_ntlm();

resp = pop3_send_cmd( socket:soc, cmd:msg3);

if (empty_or_null(resp) || (resp['text'] !~ "^\+ .*"))
{
  close(soc);
  audit(AUDIT_RESP_NOT, port, "NTLM", protocol);
}

resp = pregmatch(pattern:"(\+ *)(.*)", string:resp['text'], icase:TRUE);

resp = resp[2];

endmsg = close_pop3_connect(socket:soc);

if (!empty_or_null(endmsg) && !empty_or_null(endmsg['text']) && endmsg['text'] =~ "\+OK .*")
{
  endmsg = pregmatch(pattern: "(\+OK) *(.*)", string:endmsg['text'], icase:TRUE);
  if (!empty_or_null(endmsg[2]))
  {
    endmatch = pregmatch(pattern:" *(.*) ([0-9]*) POP3 server version ([0-9.]*) signing off.", string:endmsg[2], icase:TRUE);
  }
}

index = 0;
report_array = make_array();
order = make_list();

set_kb_item(name:'pop3/' + port + '/banner', value:chomp(banner));
if (!empty_or_null(startmatch))
{
  if (!empty_or_null(startmatch[1]))
  {
    set_kb_item(name:'pop3/' + port, value:TRUE);
    set_kb_item(name:'pop3/' + port + '/software', value:startmatch[1]);
    order[index] = "software";
    report_array["software"] = chomp(startmatch[1]);
    index++;
  }
  if (!empty_or_null(startmatch[3]))
  {
    set_kb_item(name:'pop3/' + port + '/version', value:startmatch[3]);
    order[index] = "version";
    report_array["version"] = chomp(startmatch[3]);
    index++;
  }
  if (!empty_or_null(startmatch[2]))
  {
    set_kb_item(name:'pop3/' + port + '/name', value:startmatch[2]);
    order[index] = "name";
    report_array["name"] = chomp(startmatch[2]);
    index++;
  }
  if (!empty_or_null(startmatch[4]))
  {
    set_kb_item(name:'pop3/' + port + '/dns_info', value:startmatch[4]);
    order[index] = "dns_info";
    report_array["dns_info"] = chomp(startmatch[4]);
    index++;
  }
}
else
{
  order[index] = "banner";
  report_array["banner"] = chomp(banner);
  index++;
}

if (!empty_or_null(endmsg[2]))
{
  set_kb_item(name:'pop3/' + port + '/exit_message', value:chomp(endmsg[2]));
  if (!empty_or_null(endmatch))
  {
    replace_kb_item(name:'pop3/' + port + '/software', value:endmatch[2]);
    if (empty_or_null(report_array["software"]) && !empty_or_null(endmatch[1]))
    {
      order[index] = "software";
      report_array["software"] = chomp(endmatch[1]);
      index++;
    }

    replace_kb_item(name:'pop3/' + port + '/version', value:endmatch[3]);
    if (empty_or_null(report_array["version"]) && !empty_or_null(endmatch[3]))
    {
      order[index] = "version";
      report_array["version"] = chomp(endmatch[3]);
      index++;
    }
  }
  else
  {
   order[index] = "exit_message";
   report_array["exit_message"] = chomp(endmsg[2]);
   index++;
  }
}

resp = chomp(resp);
resp_blob = base64_decode(str:resp);
parser = new("ntlm_parser", resp_blob);
parser.parse();

foreach (item in ["netbios_domain_name",
                  "netbios_computer_name",
                  "dns_domain_name",
                  "dns_computer_name",
                  "dns_tree_name",
                  "os_version",
                  "target_realm"])
{
  set_kb_item(name: "pop3/" + port + '/ntlm/host/' + item, value:parser.get(item));
  if ((item == 'os_version') || (item == 'netbios_computer_name') || (item == 'target_realm'))
  {
    order[index] = item;
    report_array[item] = parser.get(item);
    index++;
  }
}

if (!empty_or_null(auth_methods))
{
  set_kb_item(name: "pop3/" + port + "/auth", value:auth_methods);
  order[index] = "authentication methods";
  report_array["authentication methods"] = auth_methods;
  index++;
}

report = NULL;
report = '\nPOP3 NTLM Message Disclosure:\n';
report += report_items_str(report_items:report_array, ordered_fields:order);

security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
