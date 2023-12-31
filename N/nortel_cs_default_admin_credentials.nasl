#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72600);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/11/21 16:18:53 $");

  script_name(english:"Nortel CS Signaling Server Default Admin Credentials");
  script_summary(english:"Tries to log into the remote host");

  script_set_attribute(attribute:"synopsis", value:"The remote system can be accessed with a default account.");
  script_set_attribute(
    attribute:"description",
    value:
    "The remote device is a Nortel CS Signaling Server that uses a set of
    known, default credentials.  Knowing these, an attacker able to connect
    to the service can gain complete control of the device."
    );
  script_set_attribute(attribute:"see_also", value:"https://downloads.avaya.com/css/P8/documents/100098406");
  script_set_attribute(attribute:"solution", value:"Log into the remote host and change the default login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:X/RC:X");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nortel:communications_server");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl", "account_check.nasl", "telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}


include("audit.inc");
include("default_account.inc");
include("global_settings.inc");


if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


cmd = "swVersionShow";
cmd_regex = "Loaded Modules:";
login = "admin1";
password = "0000";

affected = FALSE;
ssh_ports = get_service_port_list(svc: "ssh", default:22);
foreach port (ssh_ports)
{
  ssh_port = check_account(login:login, password:password, 
                           check_mocana:TRUE, noexec:TRUE, cmd:cmd, 
                           cmd_regex:cmd_regex, port:port, 
                           svc:"ssh");
  if (ssh_port)
  {
    affected = TRUE;
    report = default_account_report(cmd:cmd);
    if (egrep(pattern:"^sse-[0-9](\.[0-9]+)+ ", string:report))
    {
      report = str_replace(find:cmd+'\r\n', replace:'', string:report);
      report = str_replace(find:'\r\n', replace:'\n  ', string:report);
      report = report - '\n  Loaded Modules:';
      report = chomp(report);
    }
    security_report_v4(port:ssh_port, severity:SECURITY_HOLE, extra:report);
  }
}
if(affected) exit(0);

telnet_ports = get_service_port_list(svc: "telnet", default:23);
foreach port (telnet_ports)
{
  telnet_port = check_account(login:login, password:password, 
                              check_mocana:TRUE, noexec:TRUE, cmd:cmd,
                              cmd_regex:cmd_regex, port:port, 
                              svc:"telnet");
  if (telnet_port)
  {
    affected = TRUE;
    report = default_account_report(cmd:cmd);
    if (egrep(pattern:"^sse-[0-9](\.[0-9]+)+ ", string:report))
    {
      report = str_replace(find:cmd+'\r\n', replace:'', string:report);
      report = str_replace(find:'\r\n', replace:'\n  ', string:report);
      report = report - '\n  Loaded Modules:';
      report = chomp(report);
    }
    security_report_v4(port:telnet_port, severity:SECURITY_HOLE, extra:report);
  }
}
if (!affected) audit(AUDIT_HOST_NOT, "affected");
