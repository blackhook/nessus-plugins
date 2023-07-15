#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99133);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_xref(name:"IAVT", value:"0001-T-0804");

  script_name(english:"Firebird SQL Server for Linux Installed (credentialed check)");
  script_summary(english:"Detects Firebird SQL Server for Linux.");

  script_set_attribute(attribute:"synopsis", value:
"An open source database server is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Firebird SQL Server, an open source database server, is installed on
the remote Linux host.");
  script_set_attribute(attribute:"see_also", value:"https://www.firebirdsql.org/");;
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"agent", value:"unix");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:firebirdsql:firebird");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");

  exit(0);
}

include("install_func.inc");
include('local_detection_nix.inc');

ldnix::init_plugin();

var appname = "Firebird SQL Server";
var version = NULL;

var rpms = get_kb_list("Host/*/rpm-list");
if(empty_or_null(rpms)) audit(AUDIT_PACKAGE_LIST_MISSING);
var distro = keys(rpms);
distro = distro[0];
rpms   = rpms[distro];

# Get the RPM version
# FirebirdCS and FirebirdSS are for 2.x
# Firebird is for 3.x
var matches = pregmatch(string:rpms, pattern:"(^|\n)(Firebird(CS|SS|)-([0-9.]+)-\d+)\|");
if (empty_or_null(matches)) audit(AUDIT_PACKAGE_NOT_INSTALLED, appname);
version = matches[4];
var package = matches[2];

register_install(
  vendor:"FirebirdSQL",
  product:"Firebird",
  app_name:appname,
  path:"unknown",
  version:version,
  cpe:"cpe:/a:firebirdsql:firebird",
  extra:make_array("Installed package", package)
);
report_installs(app_name:appname);
