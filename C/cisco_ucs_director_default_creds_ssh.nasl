#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78768);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/11/21 16:18:53 $");

  script_name(english:"Cisco UCS Director Default Credentials (SSH)");
  script_summary(english:"Tries to login with default credentials.");

  script_set_attribute(attribute:"synopsis", value:"An account on the remote host uses a default password.");
  script_set_attribute(attribute:"description", value:
"The account 'shelladmin' is using a default password. A remote,
unauthenticated attacker can exploit this to log in as a privileged
user and gain access to the Cisco UCS Director configuration menu.");
  script_set_attribute(attribute:"solution", value:"Log into the application and change the default login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:X/RC:X");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:ucs_director");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl", "account_check.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("default_account.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

login = "shelladmin";
password = "changeme";

affected = FALSE;
ssh_ports = get_service_port_list(svc: "ssh", default:22);
foreach port (ssh_ports)
{
  port = check_account(login:login, password:password, cmd:'', cmd_regex:'Cisco UCS Director', port:port, svc:"ssh");
  if (port)
  {
    affected = TRUE;
    security_report_v4(port:port, severity:SECURITY_HOLE, extra:default_account_report());
  }
}
if(affected) exit(0);

telnet_ports = get_service_port_list(svc: "telnet", default:23);
foreach port (telnet_ports)
{
  port = check_account(login:login, password:password, cmd:'', cmd_regex:'Cisco UCS Director', port:port, svc:"telnet");
  if (port)
  {
    affected = TRUE;
    security_report_v4(port:port, severity:SECURITY_HOLE, extra:default_account_report());
  }
}
if(!affected) audit(AUDIT_HOST_NOT, "affected");