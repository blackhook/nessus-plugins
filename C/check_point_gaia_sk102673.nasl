#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(104997);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2014-6271", "CVE-2014-7169");
  script_bugtraq_id(70103, 70137);
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/28");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"Check Point Gaia Operating Bash Code Injection (sk102673)(SHELLSHOCK)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Gaia OS which is affected by issues
related to the SHELLSHOCK set of vulnerabilities in bash. An error in the bash 
functionality that evaluates specially formatted environment variables passed 
to it from another environment, which may result in remote code execution.");
  # https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk102673
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8d7a5ca");
  # https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk104443&partition=General&product=Security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba5b918a");
  script_set_attribute(attribute:"solution", value:
"Update to an unaffected version or apply vendor-supplied hotfix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-6271");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Qmail SMTP Bash Environment Variable Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:check_point:gaia_os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("check_point_gaia_os_version.nbin");
  script_require_keys("Host/Check_Point/version", "Host/Check_Point/installed_hotfixes");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Gaia Operating System";
version  = get_kb_item_or_exit("Host/Check_Point/version");
hfs      = get_kb_item_or_exit("Host/Check_Point/installed_hotfixes");
vuln     = FALSE;

if (version =~ "R7[01]")
{
  vuln = TRUE;
  fix = "Upgrade to an unaffected version or contact Checkpoint support.";
}
else if (version =~ "R75\.4[0567]" || version =~ "R76" || version =~ "R77(\.[12]0)?$")
{
  if(!("sk102673" >< hfs && "sk104443" >< hfs))
    vuln = TRUE;
  fix = "Apply Hotfix sk102673 or sk104443";
}
else
  audit(AUDIT_DEVICE_NOT_VULN, "The remote device running " + app_name + " (version " + version + ")");

if(vuln)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fix               : ' + fix +
    '\n';
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_DEVICE_NOT_VULN, "The remote device running " + app_name + " (version " + version + ")");
