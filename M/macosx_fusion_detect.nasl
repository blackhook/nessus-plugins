#TRUSTED 35d1e24a3e25f60f35dd97d36ad544081fa125c23ede33f7ece1197f8c85e0a21666accc920668f576ae84330a5b9847014dbc9683cfb4334473705c7f68da0b1fc8a458002fde5b3b921d8e30222760cdfe3b279f2e523f67caffe65d47a406a8033539d82b518ec0e108b0a9b68680469bef87b606ebc1dd5b3cccd0f5f55ec30322918e0867c2adf2083682aa8b056feabc0f825474b17478ca9d076b2bb2dcade20ac2e6103df9eba4b985e372180b2c503383426af5e41e4cd20ac1eadb5206176ce052be9f95f3d34e35fdc79c00e6953a05ee7ac1714a59042b8066d7f75c2f4204826d9a1bb0da0e3403163b64a8026cd74cdc894c09cef6a97b76306f0f615f1e2c7ad540abdcfd931d02f0d2aa7f8b5ec115a7dc173a97df9b9b8e76837148a9ae8f6dcc5099769c15b6c33162efa0e0b4a2765ba714d23a268308c9bf5ba2e304bd940f1e20cc515b72af900905246937bb967f24c84c25b6ae6d9abd5b04df5993ae0701b95f84cee371f578b335767a7b9186979b08e694aad9fe198d04d7d2d0883db68b3cab2101513085ae9ae950ea008abc5aa2a0d76c9809f924f27ec206abd1638f7560a384e1a900b2e0d2f7c999e31b4b2fc91dfde7d9ea982f603695c3120e24983586f38120361a47c49a8ccf94d67355af8d341fdc75e96560d2ef697b581b811343d6ea7057272d441cf9fa49092c86b34729b3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50828);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_xref(name:"IAVT", value:"0001-T-0735");

  script_name(english:"VMware Fusion Version Detection (Mac OS X)");
  script_summary(english:"Checks the version of VMware Fusion");

  script_set_attribute(attribute:"synopsis", value:"The remote Mac OS X host has a copy of VMware Fusion installed.");
  script_set_attribute(attribute:"description", value:
"The remote host is running VMware Fusion, a popular desktop
virtualization software.");
  script_set_attribute(attribute:"solution", value:
"Make sure use of this program agrees with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("macosx_func.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("install_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

appname = "VMware Fusion";
kb_base = "MacOSX/Fusion/";

if (!get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

path = "/Applications/VMware Fusion.app";
plist = path + "/Contents/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) audit(AUDIT_NOT_INST, appname);

if (version !~ "^[0-9]") exit(1, "The " + appname + " version does not look valid (" + version + ").");

set_kb_item(name:kb_base+"Installed", value:TRUE);
set_kb_item(name:kb_base+"Path", value:path);
set_kb_item(name:kb_base+"Version", value:version);

register_install(
  app_name:appname,
  vendor : 'VMware',
  product : 'Fusion',
  path:path,
  version:version,
  cpe:"cpe:/a:vmware:fusion");

report_installs(app_name:appname);

