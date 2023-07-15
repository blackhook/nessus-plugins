#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72813);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/26");

  script_cve_id("CVE-2014-0329");
  script_bugtraq_id(65310);
  script_xref(name:"EDB-ID", value:"31527");

  script_name(english:"ZTE ZXV10 W300 Wireless Router Hard-coded Password");
  script_summary(english:"Tries to login using hard-coded credentials");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is using a known set of hard-coded credentials.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to login to the remote device using a known hard-coded
password (prepended with a portion of the device's MAC address obtained
from an SNMP request) for the admin account.  Attackers can exploit this
vulnerability to gain full control of the device.");
  # http://alguienenlafisi.blogspot.com/2014/02/hackeando-el-router-zte-zxv10-w300-v21.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aad205ef");
  script_set_attribute(attribute:"see_also", value:"https://www.kb.cert.org/vuls/id/228886/");
  script_set_attribute(attribute:"solution", value:
"There is no known fix.  As a workaround, use firewall rules to block
SNMP and telnet access.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0329");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:zte:zxv10_w300");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("snmp_settings.nasl", "find_service2.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("default_account.inc");
include("global_settings.inc");
include("snmp_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

community = get_kb_item("SNMP/community");
if (!community) community = 'public';

port = get_kb_item("SNMP/port");
if (!port) port = 161;

if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, "UDP", port);

soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");

mac = NULL;

res = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.2.2.1.6.10000");

if (!isnull(res) && strlen(res) == 6)
  mac = hexstr(res);

if (isnull(mac) && islocalnet())
  mac = get_kb_item('ARP/mac_addr');

if (isnull(mac)) exit(0, 'Failed to determine the MAC address of the remote device.');

password = substr(toupper(str_replace(string:mac, find:':', replace:'')), 8, 11) + 'airocon';

affected = FALSE;
ssh_ports = get_service_port_list(svc: "ssh", default:22);
foreach port (ssh_ports)
{
  port = check_account(login:"admin",
                       password:password,
                       unix:FALSE,
                       cmd:"show status",
                       cmd_regex:"(System[^\$]*LAN Configuration[^\$]*WAN Configuration[^\$]*)\$",
                       out_regex_group: 1,
                       check_telnet: TRUE,
                       port:port,
                       svc:"ssh");
  if (port)
  {
    affected = TRUE;
    report = '\nNessus was able to login using the following credentials : \n' +
             '\n  Username : admin' +
             '\n  Password : ' + password + '\n' +
             default_account_report(cmd:"show status");
    security_report_v4(port:port, severity:SECURITY_HOLE, extra:report, proto:"udp");
  }
}
if(affected) exit(0);

# If no SSH ports were found to be vulnerable, try telnet.
telnet_ports = get_service_port_list(svc: "telnet", default:23);
foreach port (telnet_ports)
{
  port = check_account(login:"admin",
                       password:password,
                       unix:FALSE,
                       cmd:"show status",
                       cmd_regex:"(System[^\$]*LAN Configuration[^\$]*WAN Configuration[^\$]*)\$",
                       out_regex_group: 1,
                       check_telnet: TRUE,
                       port:port,
                       svc:"ssh");
  if (port)
  {
    affected = TRUE;
    report = '\nNessus was able to login using the following credentials : \n' +
             '\n  Username : admin' +
             '\n  Password : ' + password + '\n' +
             default_account_report(cmd:"show status");
    security_report_v4(port:port, severity:SECURITY_HOLE, extra:report, proto:"udp");
  }
}
if(!affected) audit(AUDIT_HOST_NOT, "affected");