#TRUSTED 8f1f081779edb3180e6bc311a7507bbc85394846c22da2a566653c1166c9336a39747ccb576c72c78bdc8bd8a8b6d66ab5148f5035f49897d81813f29f42ae2c1b24eb0e24eed59931adf1ae340bf36e5b4788e49b36812a7cae2b28a960070cabcd5d3096ad3a46a610d0ffbd74da278d397216f2a78be540b08dc7b4e71fa50f3adb98cc6119f847dff65dc25e419ad1c8c5850e6dbcf5345a012586e633b279cc9842a1801f42677f61bca0aa3110cafca304fee7cc3d9125860f7d2af9e124feed623671f1bd49295b3f1876ab3ebc5940b6d71688353689271bdeab36604a3611de26e07da207f1c58b0ea4cda2948100becce4fc8c209bbfda007335ca454627bdf0049a0ccc9b18ed3a4dcfb809fa8a6721d34ad755f3f3c9ce1cd1960f7eec62e5f124b484664f2163efa86adc5318c66d1d1cc2f7bb58a9c69003206583c64a64663ff2c2e5cc69e354516ed6aa216c86197d2430b134287f2f5c0aa5104604cd1494132c9bccfcc2940f78fad4f1a8718f58822abdf03a5674f98afcd4f23136579bf24a3d742f00edbf037caeb178c7554d9b1a402d09030f73c8e230db2331e7673b03689649f6929ffadc0af51770224238012a15f76df08be48090ef5627db7027939c73a13ef0d125cea56c7934f1e8374f107071aa59047866e91cf2c240ce1134d9284160402e644ab1f0be3792702fc1ad29b09a47efc9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65673);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_name(english:"Novell Messenger Client Detection (Mac OS X)");
  script_summary(english:"Detects installs of Novell Messenger (formerly GroupWise Messenger) Client");

  script_set_attribute(attribute:"synopsis", value:"The remote host has an instant messaging client installed.");
  script_set_attribute(attribute:"description", value:
"The remote host has Novell Messenger (formerly GroupWise Messenger)
client installed. This is an instant messaging client based on Novell
eDirectory.");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/documentation/novell_messenger22/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:messenger");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise_messenger");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("install_func.inc");

app = "Novell Messenger Client";

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

kb_base = "MacOSX/Novell_Messenger_Client";

path = '/Applications/Messenger.app';
plist = path + '/Contents/Info.plist';

# Messenger.app is not very unique, so double check this is a
# Novell Product
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | grep \'string\'';
plist_string_contents = tolower(exec_cmd(cmd:cmd));
if("novell" >!< plist_string_contents && 'groupwise' >!< plist_string_contents)
  audit(AUDIT_NOT_INST, app);

cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);

if (!strlen(version)) audit(AUDIT_NOT_INST, app);

set_kb_item(name:kb_base+"/Installed", value:TRUE);

if (version !~ "^[0-9]") audit(AUDIT_VER_FAIL, app);

set_kb_item(name:kb_base+"/Version", value:version);
set_kb_item(name:kb_base+"/Path", value:path);

register_install(
  app_name:app,
  vendor : 'Novell',
  product : 'GroupWise Messenger',
  path:path,
  version:version,
  cpe:"cpe:/a:novell:messenger");

report_installs(app_name:app);

