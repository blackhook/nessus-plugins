#TRUSTED 8f3e1f0a80cf7ee329f95fc5bb09370c84b58bd8112ede9b97c141d7621f80b8bfdeefa8ab0015ec998288f5192affda3c9ff22886f63b2aa7e0b9da57b9b212fce5fbed3b211f7308e433e0615a81bd2298451196d635b12adf7c29f8ad314125e1da4bd923f0e65d69b8ece2bbc58e3d44f0167cbf223cb0ead1ddb8b9ddc6d62c800a7110a13ae7da247198af16c53a0dc737222e9d3bf73d3d8ed25fa7a270953c03876d4e4c3843e2c0c22c996a93335664a8387631224df990702a902c3130f0eeedfd433c7e244c394c176aa93088404eb800722e199533f6aa3ecf75b8a930576a032a9c0c8787ef0293040683c93971751f057afb8f7ff993cb023dc62ba2a2becfc76568da507277fb3e5651d3eb0839edc5a516eb02a6d9e2840080ffa6dd5a37c0957fecf2a4bcea597f3fe3fa72ea2b7850111932c473ebd1601a44c9cdf5b2322c4edb0e9834c86f7055f6efadf89fda827434d84a222e04cb7864afb7238a15e0c2c0c0513b26fb8dc531dd141c2bae80f5a9a538c8023b275765e2e58bcd826c501a5ec8e908a3db86936dcf95bdaee087f62a69d37edf0c22f68b76458fc1fa5ec4c55453851a661d612056d56931b2a2d5691eb781efe11c11ecb65be449af4ebade4dc14c63fa44b189d32992234975c3edb487952155e9cbe6b14c3955303acdd88fb520e7101c58193fe505123effe290915fc3a2d3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58091);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_name(english:"Microsoft Silverlight Installed (Mac OS X)");
  script_summary(english:"Reads version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:"The remote host has Microsoft Silverlight installed.");
  script_set_attribute(attribute:"description", value:
"A version of Microsoft Silverlight is installed on this host.

Microsoft Silverlight is a web application framework that provides
functionalities similar to those in Adobe Flash, integrating
multimedia, graphics, animations and interactivity into a single
runtime environment.");
  script_set_attribute(attribute:"see_also", value:"http://silverlight.net/");
  script_set_attribute(
    attribute:"see_also",
    value:"https://en.wikipedia.org/wiki/Silverlight"
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

app = "Microsoft Silverlight";

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


kb_base = "MacOSX/Silverlight";


path = '/Library/Internet Plug-Ins/Silverlight.plugin';
plist = path + '/Contents/Info.plist';
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' 2>/dev/null | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) exit(0, "Silverlight does not appear to be installed.");
set_kb_item(name:kb_base+"/Installed", value:TRUE);
set_kb_item(name:kb_base+"/Path", value:path);

if (version !~ "^[0-9]") exit(1, "The Silverlight version does not look valid (" + version + ").");
set_kb_item(name:kb_base+"/Version", value:version);

register_install(
  app_name:app,
  vendor : 'Microsoft',
  product : 'Silverlight',
  path:path,
  version:version,
  cpe:"cpe:/a:microsoft:silverlight");

report_installs(app_name:app);

