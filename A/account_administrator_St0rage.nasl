#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

var account = "administrator";
var password = "St0r@ge!";

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(107196);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Default Password 'St0r@ge!' for 'administrator' Account");

  script_set_attribute(attribute:"synopsis", value:
"The remote system can be accessed with a default administrator
account.");
  script_set_attribute(attribute:"description", value:
"The account 'administrator' on the remote host has the default
password 'St0r@ge!'. A remote attacker can exploit this issue to gain
administrative access to the affected system.");
  script_set_attribute(attribute:"solution", value:
"Change the password for this account or disable it.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score from an in depth analysis done by Tenable");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");

  script_copyright(english:"This script is Copyright (C) 2018-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "ssh_detect.nasl", "account_check.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22);

  exit(0);
}

include("default_account.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (! thorough_tests && ! get_kb_item("Settings/test_all_accounts"))
 exit(0, "Neither thorough_tests nor 'Settings/test_all_accounts' is set.");

var affected = FALSE;

var ssh_ports = get_service_port_list(svc:"ssh", default:22);

foreach port (ssh_ports)
{
  port = check_account(login:account, password:password, unix:FALSE, port:port, svc:"ssh");
  if (port)
  {
    affected = TRUE;
    security_report_v4(port:port, severity:SECURITY_HOLE, extra:default_account_report());
  }
}
if (affected) exit(0);

var telnet_ports = get_service_port_list(svc: "telnet", default:23);

foreach port (telnet_ports)
{
  port = check_account(login:account, password:password, unix:FALSE, port:port, svc:"telnet");
  if (port)
  {
    affected = TRUE;
    security_report_v4(port:port, severity:SECURITY_HOLE, extra:default_account_report());
  }
}
if (!affected) audit(AUDIT_HOST_NOT, "affected");
