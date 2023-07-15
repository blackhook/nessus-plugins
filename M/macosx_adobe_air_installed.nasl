#TRUSTED 90e2ce477827b71724f9c0d726d044e4c6768d44d6698ae142e4be768f11856186982ec8e2837242417ce587597324a004313f3d59d4a21e997f93d09d920b604342c28cbf6b91a02e1c6f0311aa0e08906de9bb4cc177c97aba1b7a5dbaeec881f8e8b445804bd52e6fe062e70a6a9fdfa04140c7422626c6e96cb795d712e3f2ae288a6bc51a6c8272e6505721e72ef0edb6b65f159608ef9b207abea865de830ee60d97bc09deda260f3647bc8352797a1f0ff65c56395471e9e40b959ea208c00aefe468f96b0cf8d57874c39f6df8aca5d03cb096f25de6c2fa7f7443d45ffc8247b99b4efd97587a409609792b720b7780c9b6305890de2a60a32327cfcf1ba0bbd2b55bf32fc43f2d2ee860442c4fcfe8b3ddeffc17a46c72d00cf44c8ad91623f30ee7e2f2d57a0ee68e93bd965417462d4208bf51b5a0b6add86b7b51a16311ae165afbd780bc1beb1dba0b30bc7711e98a2736b5bd14f20a32c82d1059084a74f13c432e898813cd08d70745383b2daac5b64d59bb58f8ccfb86688d3670b662768eab4e07b06acd90cc514828204ca96c6898f495cc1f4b02fff155273d2d50a71315f1594a5635d23d5af054e21f5df784fc43ffd090fd30f341e137451498328bc042db25509255ec50c0573b9f8cab3849c5827a78d6e8da511c243c79ab24075ec652aa63e39be4506a37e707c007cbbefa284f936be931eb
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56960);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_name(english:"Adobe AIR for Mac Installed");
  script_summary(english:"Gets AIR version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:"The remote Mac OS X host contains a runtime environment.");
  script_set_attribute(attribute:"description", value:
"Adobe AIR for Mac is installed on the remote host. It is a browser-
independent runtime environment that supports HTML, JavaScript, and
Flash code and provides for Rich Internet Applications (RIAs).");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/air.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("audit.inc");
include("install_func.inc");

app = "Adobe AIR";

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");


os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


path = '/Library/Frameworks/Adobe AIR.framework';
plist = path + '/Versions/Current/Resources/Info.plist';
cmd =
  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (isnull(version)) exit(0, "Adobe AIR is not installed.");
if (version !~ "^[0-9]") exit(1, "Failed to get the version - '" + version + "'.");

set_kb_item(name:"MacOSX/Adobe_AIR/Path", value:path);
set_kb_item(name:"MacOSX/Adobe_AIR/Version", value:version);

register_install(
  app_name:app,
  vendor : 'Adobe',
  product : 'AIR',
  path:path,
  version:version,
  cpe:"cpe:/a:adobe:air");

report_installs(app_name:app);

