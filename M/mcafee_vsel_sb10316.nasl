#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136666);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-7267");
  script_xref(name:"MCAFEE-SB", value:"SB10316");
  script_xref(name:"IAVA", value:"2020-A-0202");

  script_name(english:"McAfee VirusScan Enterprise for Linux <= 2.0.3 Multiple vulnerabilities (SB10316)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of McAfee VirusScan Enterprise for Linux
(VSEL) installed that is prior or equal to 2.0.3. It is, therefore,
affected by a privilege escalation vulnerability which allows
a malicious attacker the ability to delete files they do not have access to.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10316");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VSEL 2.0.3 Security Hotfix 2635000 or VSEL 1.9.2 Security Hotfix 2637000");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7267");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:virusscan_enterprise");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_vsel_detect.nbin");
  script_require_keys("installed_sw/McAfee VirusScan Enterprise for Linux");

  exit(0);
}

include('install_func.inc');

var app_name = "McAfee VirusScan Enterprise for Linux";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

var install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
var version = install['version'];
var vuln = FALSE;

if (ver_compare(ver:version, fix:"2.0.3.29216", strict:FALSE) < 0 && version =~ "^2\.0\.3") vuln = TRUE;
else if (ver_compare(ver:version, fix:"1.9.2.29197", strict:FALSE) < 0 && version =~ "^1\.9\.2") vuln = TRUE;

var port, report;
if (vuln)
{
  port = 0;
  report ='\nInstalled version : ' + version +
          '\nSolution          : Upgrade to McAfee VirusScan Enterprise (VSE) for Linux 1.9.2 Hotfix 2637000, 2.0.3 Hotfix 2635000, or later.\n';
  security_report_v4(severity:SECURITY_NOTE, extra:report, port:port, xss:TRUE, sqli:TRUE, xsrf:TRUE);
}
else audit(AUDIT_INST_VER_NOT_VULN, version);
