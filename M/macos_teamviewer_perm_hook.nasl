#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105110);
  script_version("1.4");
  script_cvs_date("Date: 2018/08/08 12:52:14");


  script_name(english:"TeamViewer Permissions Vulnerability (macOS)");
  script_summary(english:"Checks the version of TeamViewer.");

  script_set_attribute(attribute:"synopsis", value:
"The remote macOS or Mac OS X host contains an application that is affected by a
permissions vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the TeamViewer install on the remote
macOS or Mac OS X host is a version prior to 11.0.73955, 12.0.82953, or 13.0.5640.
It is, therefore, affected by a permissions vulnerability than can result
in unauthorized remote control.

During an authenticated connection it may be possible for an attacker to 
control the mouse without regard for the server's current control setting. 
This can be exploited from both the viewer and presenter roles, enabling the 
viewer to control the presenters mouse or enabling the 'switch sides' feature without 
requiring the client to agree.");
  #https://threatpost.com/teamviewer-rushes-fix-for-permissions-bug/129096/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b468dce");
  script_set_attribute(attribute:"see_also", value:"https://github.com/gellin/TeamViewer_Permissions_Hook_V1");
  #https://www.teamviewer.com/en/company/press/teamviewer-releases-hotfix-for-permission-hook-vulnerability/ 
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?049e3175");
  
  script_set_attribute(attribute:"solution", value:
"Upgrade to TeamViewer 11.0.73955 / 12.0.82953 / 13.0.5640 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:teamviewer:teamviewer");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("macos_teamviewer_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/TeamViewer");

  exit(0);
}

include("audit.inc");
include("vcf.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item('Host/MacOSX/Version');
if (!os) audit(AUDIT_OS_NOT, 'Mac OS X or macOS');

app = 'TeamViewer';

app_info = vcf::get_app_info(app:app);
if (app_info.version !~ "^(11.|12.|13.)") audit(AUDIT_INST_VER_NOT_VULN, app, app_info.version);

constraints = [
  { "min_version" : "11", "fixed_version" : "11.0.73955" },
  { "min_version" : "12", "fixed_version" : "12.0.82953" },
  { "min_version" : "13", "fixed_version" : "13.0.5640" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
