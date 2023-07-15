#
# (C) Tenable Network Security, Inc,
#

include("compat.inc");

if (description)
{
  script_id(131765);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/10");

  script_cve_id("CVE-2019-18374");
  script_bugtraq_id(110877);
  script_xref(name:"IAVA", value:"2019-A-0440");

  script_name(english:"Symantec Critical System Protection 8.0 < 8.0 MP2 Authentication Bypass (SYMSA1498)");
  script_summary(english:"Checks the version of Symantec Critical System Protection.");

  script_set_attribute(attribute:"synopsis", value:
"The remote windows host has a security application installed that is affected by an authentication bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Critical System Protection (SCSP) installed on the remote Windows host is 8.0 prior to 8.0
MP2. It is, therefore, affected by an unspecified authentication bypass vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://support.symantec.com/us/en/article.symsa1498.html");
  # https://www.symantec.com/security-center/vulnerabilities/writeup/110877
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b5f54eb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Critical System Protection 8.0 MP2 or later.
Alternatively, apply the workarounds referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18374");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:critical_system_protection");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_critical_system_protection_installed.nbin");
  script_require_keys("installed_sw/Symantec Critical System Protection", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

appname = "Symantec Critical System Protection";

install = get_single_install(app_name:appname);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = install['version'];
path = install['path'];
build = install['Build'];

if (version =~ "^8\.0\.0$")
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version + '.' + build +
    '\n  Fixed version     : 8.0.0 MP2' +
    '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version + '.' + build, path);
