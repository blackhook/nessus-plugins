#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

account = "root";
password = "password";

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(24745);
  script_version("1.30");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-1999-0502", "CVE-2006-5288", "CVE-2012-4577");
  script_bugtraq_id(20490, 55196);
  script_xref(name:"ICSA", value:"12-263-02");
  script_xref(name:"ICSA", value:"12-297-02");

  script_name(english:"Default Password (password) for 'root' Account");

  script_set_attribute(attribute:"synopsis", value:
"An administrative account on the remote host uses a weak password.");
  script_set_attribute(attribute:"description", value:
"The account 'root' has the password 'password'.  An attacker may use
it to gain further privileges on this system.

Note that Korenix Jetport installs are known to use these credentials
although other hosts are likely to as well as 'password' is reportedly a
common password.");
  script_set_attribute(attribute:"see_also", value:"http://www.digitalbond.com/2012/06/13/korenix-and-oring-insecurity/");
  script_set_attribute(attribute:"solution", value:
"Set a strong password for this account or disable it.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:TF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:T/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"metasploit_name", value:'SSH User Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");

  script_copyright(english:"This script is Copyright (C) 2007-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl", "ssh_detect.nasl", "account_check.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22);

  exit(0);
}

#
# The script code starts here : 
#
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

