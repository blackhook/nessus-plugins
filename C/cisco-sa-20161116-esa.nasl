#TRUSTED 43975100fddbd61042386b63eef225c4013a3cca790200020887d66381c59c20ba176835f8cf9b5dbfa846a3195bbb9f70874a801676c011046eceabecdecd0affe8587ee9097762f160927c7e7237982bac66e63297bae552ef69177cf76e1c1732cdc6d93cfdf0899e5f9e3a399887282f6bf9ba686ebb5dfef473bf3f8cdff351695cb2d7052dc0f1e4777a732d4a493f6ee906d0d9efc7df782c5c2affe7293ec2c5a9e2a4b1ff7214397934f4e4fa052e84b0d0fd88e7cffe44a8639b01fb69b9ef6aa5d758780faa67d2e58cdb0486b3639c04658dc3ad27e2ed64f5e3550297a16d19e3f1fdfd5f1bc24c4b1b6280b787a244eed15d5a0f908050407cdce763d60d385795287d15dc5fcf97c7251ed8e7c38c1345a8d095d481f778e8f533274a57e56391caaabc89539e6e2ea1bff49916d4d6a3fd3e6fc7040fe275db659d7571be86c8182fb5027e37dba298177d8792465ec19547047fde20cbfc736adca1aff97e24f30dabf06e56493bdcc6c181c1ba8dbf18d3dac75092336c75c3483b47e9fdbf35a543cad7017ccd8d21470d8c6f78bb29406c596d2497926e146a2e2359afdd523d437f175418bb4dcbaedbd8cfb95153a614985568e8034386b7052557e2ebe38eeab43fc3792b50e3a73cc251eaca5081b85e88cb8402ea71bace47cc026664dddf6276b2581bb63c6f5adb054817bf8dea4d59208db5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95479);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2016-6462", "CVE-2016-6463");
  script_bugtraq_id(94360, 94363);
  script_xref(name:"CISCO-BUG-ID", value:"CSCva13456");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20161116-esa1");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz85823");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20161116-esa2");

  script_name(english:"Cisco AsyncOS for Email Security Appliances MIME Header Processing Filter Bypass (cisco-sa-20161116-esa1 / cisco-sa-20161116-esa2)");
  script_summary(english:"Checks the ESA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote security appliance is missing a vendor-supplied security
patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco AsyncOS running on
the remote Cisco Email Security (ESA) appliance is affected by an
email filter bypass vulnerability in the email filtering functionality
due to improper error handling when processing malformed Multipurpose
Internet Mail Extension (MIME) headers that are present in an
attachment. An unauthenticated, remote attacker can exploit this
vulnerability, via email having a specially crafted MIME-encoded
attached file, to bypass the Advanced Malware Protection (AMP) filter
configuration. Note that in order to exploit this vulnerability, the
AMP feature must be configured to scan incoming email attachments.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161116-esa1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af6ae40f");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161116-esa2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84d58db7");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant update referenced in Cisco Security Advisories
cisco-sa-20161116-esa1 or cisco-sa-20161116-esa2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6463");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:email_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Email Security Appliance/Version");
  script_require_ports("Host/local_checks_enabled", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

display_ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Email Security Appliance/DisplayVersion');
ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Email Security Appliance/Version');

if (get_kb_item("Host/local_checks_enabled")) local_checks = TRUE;
else local_checks = FALSE;

ver_fixes = make_array(
  # affected ,  # fixed
  "9.7.0.125",  "9.7.2-131",
  "9.7.1.066",  "9.7.2-131",
  "10.0.0.082", "10.0.0-203",
  "10.0.0.125", "10.0.0-203"
);

vuln = FALSE;
display_fix = NULL;
foreach affected (keys(ver_fixes))
{
  if (ver == affected)
  {
    display_fix = ver_fixes[affected];
    vuln = TRUE;
    break;
  }
}

if (isnull(display_fix))
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco ESA', display_ver);

override = FALSE;
# If local checks are enabled, confirm whether AMP is configured to
# scan incoming email attachments. If local checks not enabled, only
# report if running a paranoid scan.
if (local_checks && vuln)
{
  vuln = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/ampconfig", "ampconfig");
  if (check_cisco_result(buf) && preg(multiline:TRUE, pattern:"File Reputation: Enabled", string:buf))
    vuln = TRUE;
  else if (cisco_needs_enable(buf)) override = TRUE;
}
else if (!local_checks && report_paranoia < 2) vuln = FALSE;

if (vuln)
{
  if (!local_checks) override = TRUE;

  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    override : override,
    version  : display_ver,
    bug_id   : "CSCva13456/CSCuz85823",
    fix      : display_fix,
    cmds     : make_list("ampconfig")
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Cisco ESA', display_ver);
