#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109031);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/22");

  script_cve_id("CVE-2018-4927", "CVE-2018-4928");

  script_name(english:"Adobe InDesign CC < 13.1 Multiple Vulnerabilities (APSB18-11) (macOS)");
  script_summary(english:"Checks the InDesign version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InDesign CC installed on the remote macOS or
Mac OS X host is prior to 13.1. It is, therefore, affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/indesign/apsb18-11.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop CC version 13.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4928");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:indesign");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_indesign_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe InDesign");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item('Host/MacOSX/Version');
if (!os) audit(AUDIT_OS_NOT, 'macOS');

app = 'Adobe InDesign';
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

product = install['name'];
if ("CC" >!< product)
  exit(0, "Only Adobe InDesign CC is affected.");

path    = install['path'];
version = install['version'];

fix = '13.1';

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report = '\n  Product           : ' + product +
           '\n  Path              : ' + path +
           '\n  Installed version : ' + version +
           '\n  Fixed version     : ' + fix;

  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, app + " CC", version);
