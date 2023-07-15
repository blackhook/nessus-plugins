#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

account = "Wproot";
password = "cat1029";

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104973);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Default Password 'cat1029' for 'Wproot' Account");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an account with a default password.");
  script_set_attribute(attribute:"description", value:
"The account 'Wproot' on the remote host has the default password
'cat1029'. A remote attacker can exploit this issue to gain
administrative access to the affected system.

Note that this username / password combination was found in the leaked
source from the Mirai botnet.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Mirai_(malware)");
  # https://blog.trendmicro.com/trendlabs-security-intelligence/new-mirai-attack-attempts-detected-south-america-north-african-countries/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae5b1f64");
  script_set_attribute(attribute:"solution", value:
"Change the password for this account or disable it.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:TF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:T/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "ssh_detect.nasl", "account_check.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("default_account.inc");
include("global_settings.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (! thorough_tests && ! get_kb_item("Settings/test_all_accounts"))
 exit(0, "Neither thorough_tests nor 'Settings/test_all_accounts' is set.");

affected = FALSE;
ssh_ports = get_service_port_list(svc: "ssh", default:22);
foreach port (ssh_ports)
{
  port = check_account(login:account, password:password, port:port, svc:"ssh");
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
  port = check_account(login:account, password:password, port:port, svc:"telnet");
  if (port)
  {
    affected = TRUE;
    security_report_v4(port:port, severity:SECURITY_HOLE, extra:default_account_report());
  }
}
if(!affected) audit(AUDIT_HOST_NOT, "affected");
