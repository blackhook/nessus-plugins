#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


account = "HPSupport";
password = "badg3r5";

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67005);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-1999-0502", "CVE-2013-2342");
  script_bugtraq_id(60819);

  script_name(english:"Default Password (badg3r5) for 'HPSupport' Account");

  script_set_attribute(attribute:"synopsis", value:
"The remote system can be accessed with a default account.");
  script_set_attribute(attribute:"description", value:
"The account 'HPSupport' on the remote host has the password 'badg3r5'. 

An attacker may leverage this issue to gain administrative access to the
affected system.

Note that HP StoreOnce D2D Backup systems running software version
2.2.17 / 1.2.17 or older are known to have an account that uses these
credentials.");
  script_set_attribute(attribute:"see_also", value:"https://lolware.net/2014/05/29/hpstorage.html");
  # https://h20565.www2.hp.com/portal/site/hpsc/template.PAGE/public/kb/docDisplay/?spf_p.tpst=kbDocDisplay&spf_p.prp_kbDocDisplay=wsrp-navigationalState%3DdocId%253Demr_na-c03813919-1%257CdocLocale%253D%257CcalledBy%253D&javax.portlet.begCacheTok=com.vignette.cachetoken&javax.portlet.endCacheTok=com.vignette.cachetoken
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0eeaeffa");
  script_set_attribute(attribute:"solution", value:
"If the device is an HP StoreOnce D2D Backup system, upgrade to software
version 2.2.18 / 1.2.18 or later. 

Otherwise, set a strong password for this account or use ACLs to
restrict access to the host.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:TF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:T/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2342");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SSH User Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_detect.nasl", "account_check.nasl", "telnetserver_detect_type_nd_version.nasl");
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
  port = check_account(login:account, password:password, unix:FALSE, port:port, svc:"ssh");
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
  port = check_account(login:account, password:password, unix:FALSE, port:port, svc:"telnet");
  if (port)
  {
    affected = TRUE;
    security_report_v4(port:port, severity:SECURITY_HOLE, extra:default_account_report());
  }
}
if(!affected) audit(AUDIT_HOST_NOT, "affected");

