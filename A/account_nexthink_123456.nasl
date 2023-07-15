#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

account = "nexthink";
password = "123456";

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(82505);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-1999-0502");

  script_name(english:"Default Password (123456) for 'nexthink' Account");

  script_set_attribute(attribute:"synopsis", value:
"The remote host can be accessed with a default account.");
  script_set_attribute(attribute:"description", value:
"The account 'nexthink' on the remote host has the password '123456'.
An attacker can leverage this issue to gain administrative access to
the affected system.

Note that Nexthink is known to use these credentials to provide
administrative access to the host.");
  script_set_attribute(attribute:"see_also", value:"https://doc.nexthink.com/Documentation");
  script_set_attribute(attribute:"solution", value:
"Set a strong password for this account or use ACLs to restrict access
to the host.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0502");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SSH User Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_detect.nasl", "account_check.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ssh", 22);

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
