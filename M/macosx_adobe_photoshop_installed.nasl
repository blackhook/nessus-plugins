#
# (C) Tenable Network Security, Inc.
#

include ("compat.inc");

if (description)
{
  script_id(62220);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/27");

  script_xref(name:"IAVT", value:"0001-T-0523");

  script_name(english:"Adobe Photoshop for Mac Installed");
  script_summary(english:"Gets the Adobe Photoshop version from system_profiler.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a graphics editing application.");
  script_set_attribute(attribute:"description", value:
"Adobe Photoshop, an image editing application, is installed on the Mac
OS X host.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/photoshop.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "macosx_eval_installed.nbin");
  script_require_keys("Host/MacOSX/Version", "Host/MacOSX/packages", "MacOSX/packages/sys_profiler");

  exit(0);
}

include("install_func.inc");
include("macosx_software_eval_funcs.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

var app = "Adobe Photoshop";

var pkg_found=osx_find_installs(package:app,icase:FALSE,starts_with:TRUE,single:TRUE);

if (empty_or_null(pkg_found))
  audit(AUDIT_NOT_INST,app);

var install=get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

var product = install['name'];
var path    = install['path'];
var version = install['version'];

var report = '\n  Product           : ' + product +
             '\n  Path              : ' + path +
             '\n  Installed version : ' + version;

security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
exit(0);
