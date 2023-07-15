#TRUSTED 2ed6aa1f9204daa8d6164f23c5bfb63562d4f0efa1752c20237a4efd61cb33581e98cf50351e8cbc0a68a92941bc2bd80d5e06fdeee9a82210bf812b2fb679d70366770dc02bdcead42b4ac9059de31bb8cc37f3a4a4897828a410e32d40c9933241780a2577463c26bec5b71f565666f07bdfb8ef8af02d8290868776e973c2325fbe34b7b3e05161ee17c2ba307baee3383e5705117ef6f57f6b099bec3819b5b418cfa04bae111d7c1dbc5b4e1e86a55078fb628725c840b2a6ae9f449a2392906bb9ed15482af6d65c2856bb96517d255d219b11117b604026b8e2c83002d9842783f9c1d8e2ce939d93f0be94cedc988952aa86e4744788c9a58549b3fd10167e0a4cf5bdb23bce8b20cafada8a886315b15f232398b278d97a68b3a91a3faa5eafd18fe5742abebd906ba9902917ff4edef1ac3f710c7f3d0a7e92697bc6a73a366284e4d63e0170e6cb7e94f004d0b910ed6157f2a0289682752456ac367a3eb6b9dde2bc2af3c956fbbb731a9930e787f954cb558e0a983e82de1875524dc95ffc9e0cfddbd5f04db85a1c328bc2d1834f54c4134ca2beca71dd44dc282a4732b856c89744cf96bbb73d72911c2166cdbebd79ab236f09383c6db94854b512a6aa9a2c35c4a4ded68870983ed2ba2f727dc61da496e51b0d3d86201a8bfe9f9bbb6f872ff4f6945ed2fbdc3046fa0eeb61b0c236f90e45e8b34e1a6d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53914);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_xref(name:"IAVT", value:"0001-T-0519");

  script_name(english:"Adobe Flash Player for Mac Installed");
  script_summary(english:"Gets Flash Player version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a browser enhancement for displaying
multimedia content.");
  script_set_attribute(attribute:"description", value:"Adobe Flash Player for Mac is installed on the remote Mac OS X host.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/flashplayer/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("audit.inc");
include("install_func.inc");

app = "Flash Player";

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(0, "The 'Host/MacOSX/packages' KB item is missing.");

path = "/Library/Internet Plug-Ins/Flash Player.plugin";
plist = path + "/Contents/Info.plist";
cmd = string(
  "cat '", plist, "' | ",
  "grep -A 1 CFBundleShortVersionString | ",
  "tail -n 1 | ",
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
);
version = exec_cmd(cmd:cmd);
if (isnull(version)) exit(0, "Flash Player is not installed.");
if (version !~ "^[0-9]") exit(1, "Failed to get the version - '" + version + "'.");

set_kb_item(name:"MacOSX/Flash_Player/Path", value:path);
set_kb_item(name:"MacOSX/Flash_Player/Version", value:version);

register_install(
  app_name:app,
  vendor : 'Adobe',
  product : 'Flash Player',
  path:path,
  version:version,
  cpe:"cpe:/a:adobe:flash_player");

report_installs(app_name:app);

