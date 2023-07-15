#TRUSTED 3d336d1b2cad625c91b992f41027a2209d330f2dc74846c1ca1ace84e7838d0df519c409e5a6413d4dd9008d2d3b2ac698ffcd00b12421ae94dc6e35704ce794d385551ab2803e4db7e3c36b0ffb2452335c7819ab52c2cfd76444dcdfd31442ec2577e80bcf0e0a4c126a81ac410483508bb3cede8e4417f7218306125235535b8c864648508ca73ac7e8ff57c1fe4ece1995efb1bbdc8c1236929ba06ddf7b5429cf581084d4c7194864e74f78fe0bb1aef8a8354f860fdd3b1675b99b6b36826229a5704c6c077cbf5e6bf6923b5519470ea511519d61b9c2bb0cd3611708714d301310606746faf26fc2e5320713a5fe9b0140f957dd172cc8b88defd89e1070c828e93425e0204273b03450b8e66a4715644e60d5a8834e82b2cac5f1561db8d07ea71c1a5fc4c4e08609f7a50a9838802e26398e2bb562a44f36353ac5047f6c8fb1045c8bb667d5998224384724f6a589b474b9e706d7c439da9997654d0997a9b5260e45ab8ec3b9508e62f3e549838e459636d172ea0b9a277733f7d28c30476d00b4ee5f2c7f3269cc11369535f127d0944b37b53f6d146f49e1e1a5a483b0a9c93f730c8d8eb04c089c9a0387451af29ce3332a92c9c18ea8e561e2368695882f06e8cedb0a2304e5753bfd624d8769c256cae0fae7aff3df618140d214f55789ac047027e113430516fc83d689e54b12917b3e4cff5cb91ad6ba
#TRUST-RSA-SHA256 9e102b1f0149937782125114ff186f4b675f3a9831ad9deb18ee7ab6c9cbd1d891db1dad0b571c07734a47ddb8f7a88fda9b17702bad32438dc253f92e5e7eac9d4538668932cda16e6976f701482116adabb68894e4fb6275198aa3209d12ceac06b9a00dc641eaaf59ce32791b424f886641880f518de618fce41119d1cb50b6d754f97bb32593b1825e348bfe9734ac08acc5ae70545bf04191e9462f5e6c0824f85c3d8377a1ce868b7f2e6b3639303feab53a9aa21459e02c03d3f71d0a7f136a12c0393f71c357bcb16078b39b36dfb77e369ea4a7bfd3b1b74be2e6f4545247ed0d4d727291eed9110243f2b67d6157aed943589288e7acd33493b24803b79275bbbc394f542237d664d69c65592af4c1fc912aa8ceb4671ad63f71237b70145df74c4ef03d720294e025c6493be56c0885f49c4b9cfac54fb016de1ca9ccefc92d408f184a21b776e00ff84267da983fd6eeaeec45db11bf590221c3df78956ee166537123f4d12392b3dfa7e725fbc87f158407afad4ceff4a2b62d74540b482892329a980fa4a1e618635f0003494bee625941aeefaa968689c865bb5d5a34fd6357b1e67b0cb1b8619c5d0008be6965318f93a87451a74a6334bce4e8ab1e0693a529889e3c50b45c1cdec1f7685e6a4010a1da6396b4e2a798f496cef437899728253ce3210a991a2b2b668a54a0e52671b0431952f66e3be87a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61620);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"Apple Remote Desktop Admin Detection (Mac OS X)");
  script_summary(english:"Reads version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:"A remote management tool is installed on the remote Mac OS X host.");
  script_set_attribute(attribute:"description", value:
"Apple Remote Desktop Admin is installed on the remote Mac OS X host.
It is a tool for managing Mac computers on a network.");
  script_set_attribute(attribute:"see_also", value:"http://www.apple.com/remotedesktop/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_remote_desktop");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

app = "Apple Remote Desktop Admin";

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/MacOSX/Version"))audit(AUDIT_HOST_NOT, "running Mac OS X");

kb_base = "MacOSX/Remote_Desktop_Admin";

path = '/Applications/Remote Desktop.app';
plist = path + '/Contents/Info.plist';
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' 2>/dev/null | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) audit(AUDIT_NOT_INST, app);

set_kb_item(name:kb_base+"/Installed", value:TRUE);
set_kb_item(name:kb_base+"/Path", value:path);

if (version !~ "^[0-9]") exit(1, "The version does not look valid (" + version + ").");
set_kb_item(name:kb_base+"/Version", value:version);

register_install(
  vendor:"Apple",
  product:"Apple Remote Desktop",
  app_name:app,
  path:path,
  version:version,
  cpe:"cpe:/a:apple:apple_remote_desktop");

report_installs(app_name:app);

