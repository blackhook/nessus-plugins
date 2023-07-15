#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111138);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Default Password 'admin123' for 'admin' Account");

  script_set_attribute(attribute:"synopsis", value:
"The remote system can be accessed with a default administrator
account.");
  script_set_attribute(attribute:"description", value:
"The account 'admin' on the remote host has the default password
'admin123'. A remote attacker can exploit this issue to gain
administrative access to the affected system.");
  script_set_attribute(attribute:"solution", value:
"Change the password for this account or disable it.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Default admin credential warns high CVSS score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl", "ssh_detect.nasl", "account_check.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ssh", 22, "Services/telnet", 23);

  exit(0);
}

include("audit.inc");
include("default_account.inc");
include("global_settings.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("lists.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (! thorough_tests && ! get_kb_item("Settings/test_all_accounts"))
  exit(0, "Neither thorough_tests nor 'Settings/test_all_accounts' is set.");

account = "admin";
password = "admin123";
affected = FALSE;
ssh_ports = get_service_port_list(svc:"ssh", default:22);
telnet_ports = get_service_port_list(svc:"telnet", default:23);
ports_kbs = collib::remove_duplicates(make_list(ssh_ports, telnet_ports));

port = branch(ports_kbs);
if ((empty_or_null(port)) || (!get_port_state(port))) audit(AUDIT_NOT_LISTEN,'SSH/Telnet', port);

if (collib::contains(ssh_ports, port))
{
  affected = check_account(login:account, password:password, port:port, svc:"ssh");
}
else if (collib::contains(telnet_ports, port))
{
 affected = check_account(login:account, password:password, port:port, svc:"telnet");
}

if (affected)
{
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:default_account_report());
}
else audit(AUDIT_HOST_NOT, "affected");
