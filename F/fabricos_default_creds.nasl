#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76073);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Brocade Fabric OS Default Credentials");

  script_set_attribute(attribute:"synopsis", value:
"The remote system can be accessed with a default set of credentials.");
  script_set_attribute(attribute:"description", value:
"The remote device is a Brocade Fabric OS device that uses a set of
known, default credentials. Knowing these, an attacker able to connect
to the service can gain control of the device.");
  # https://community.brocade.com/t5/User-Contributed/How-To-Find-Default-Username-and-Password/ta-p/36420
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29d6d7e8");
  script_set_attribute(attribute:"solution", value:
"Log into the remote host and change the default login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:X/RC:X");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:brocade:fabric_os");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2022 Tenable Network Security, Inc.");

  script_dependencies("account_check.nasl", "ssh_detect.nasl", "telnetserver_detect_type_nd_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22);

  exit(0);
}


include("audit.inc");
include("default_account.inc");
include("global_settings.inc");


if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


cmd = "version";
cmd_pat = "Fabric OS:[ \t]+v[0-9]+(\.[0-9]+)+";

creds = [['admin', 'password'],
         ['root',  'fibranne']];

affected = FALSE;
ssh_ports = get_service_port_list(svc: "ssh", default:22);
foreach port (ssh_ports)
{
  report = "";
  foreach cred (creds)
  {
    port = check_account(login:cred[0], password:cred[1], noexec:TRUE,
                         cmd:cmd, cmd_regex:cmd_pat, port:port,
                         svc:"ssh");
    if (port)
    {
      report += '\n  Login : ' + cred[0] +
                '\n  Pass  : ' + cred[1] +
                '\n';
      affected = TRUE;
      if (!thorough_tests) break;
    }
  }
  if (report)
  {
    report = '\n' + 'Nessus was able to gain access using the following credentials :' +
             '\n' +
             report + default_account_report(cmd:cmd);
    security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
  }
}
if(affected) exit(0);

telnet_ports = get_service_port_list(svc: "telnet", default:23);
foreach port (telnet_ports)
{
  report = "";
  foreach cred (creds)
  {
    port = check_account(login:cred[0], password:cred[1], noexec:TRUE,
                         cmd:cmd, cmd_regex:cmd_pat, port:port,
                         svc:"telnet");
    if (port)
    {
      report += '\n  Login : ' + cred[0] +
                '\n  Pass  : ' + cred[1] +
                '\n';
      affected = TRUE;
      if (!thorough_tests) break;
    }
  }
  if (report)
  {
    report = '\n' + 'Nessus was able to gain access using the following credentials :' +
             '\n' +
             report + default_account_report(cmd:cmd);
    security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
  }
}
if(!affected) audit(AUDIT_HOST_NOT, "affected");
