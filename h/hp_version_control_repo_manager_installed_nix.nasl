#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85804);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/09");

  script_xref(name:"IAVT", value:"0001-T-0621");

  script_name(english:"HP Version Control Repository Manager Linux Detection (credentialed check)");
  script_summary(english:"Detects HP Version Control Repository Manager for Linux.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has version control repository management software
installed.");
  script_set_attribute(attribute:"description", value:
"HP Version Control Repository Manager, a software version management
application, is installed on the remote Linux host.");
  # http://www.hp.com/wwsolutions/misc/hpsim-helpfiles/mxhelp/mxportal/en/useTools_vc_about_vcrm.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6dab298");;
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"agent", value:"unix");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:version_control_repository_manager");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");

  exit(0);
}

include("install_func.inc");
include('local_detection_nix.inc');

ldnix::init_plugin();

var appname = "HP Version Control Repository Manager for Linux";

var rpms = get_kb_list("Host/*/rpm-list");
if(empty_or_null(rpms)) audit(AUDIT_PACKAGE_LIST_MISSING);
var distro = keys(rpms);
distro = distro[0];
rpms   = rpms[distro];

# Get the RPM version
var version = pregmatch(string:rpms, pattern:"(^|\n)cpqsrhmo-([0-9.]+)-\d+\|");
if (empty_or_null(version)) audit(AUDIT_VER_FAIL, appname);
version = version[2];

register_install(
  app_name:appname,
  vendor : 'HP',
  product : 'Version Control Repository Manager',
  path:"/opt/hp/vcrepository", # Nix installer gives you no choice for this
  version:version,
  cpe:"cpe:/a:hp:version_control_repository_manager"
);
report_installs(app_name:appname);
