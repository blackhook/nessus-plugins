#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


account = "dbadmin";
password = "sq!us3r";

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(42147);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-1999-0502", "CVE-2009-3710");
  script_bugtraq_id(42349);
  script_xref(name:"SECUNIA", value:"36971");

  script_name(english:"Default Password (sq!us3r) for 'dbadmin' Account");

  script_set_attribute(attribute:"synopsis", value:
"The remote system can be accessed with a default account.");
  script_set_attribute(attribute:"description", value:
"The account 'dbadmin' on the remote host has the password 'sq!us3r'. 

An attacker may leverage this issue to gain access to the affected
system. 

Note that RioRey RIOS appliances, used for dynamic denial of service
mitigation, are reported to use these credentials to support
connections from rVIEW, the vendor's central management and
configuration tool, and that an attacker reportedly may be able to
escalate privileges through several vulnerabilities to gain full
control over the device.");
  script_set_attribute(attribute:"see_also", value:"https://packetstormsecurity.com/0910-exploits/riorey-passwd.txt");
  script_set_attribute(attribute:"solution", value:
"If the affected device is a RioRey platform, contact the vendor for a
patch. 

Otherwise, change the password for this account or disable it.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:TF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:T/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"metasploit_name", value:'SSH User Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(255);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");

  script_copyright(english:"This script is Copyright (C) 2009-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl", "ssh_detect.nasl", "account_check.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22, 8022);

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

