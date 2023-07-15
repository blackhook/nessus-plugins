#TRUSTED 89f4174acf0bf0aaf990f2bfff109690189b5b68e5222ac82fedd19494f9831bb338f4bd2d9ead3dcc833c839b00344fcfc370ab3cf27aee91794da0cea240ea7d37c0df5fdfd1ae19a76d175962164b7fefee6b6537268d8c15225088e1afafefe47e79fa29ced1a9ce9ed66fe869ecd64aa287d9c73f29e289827a0069d7fd68b2814bab7896a2a318654d414ce2269a308ba06c82213c497bda5a9c5eff64ed8b76bf102b4410625b27256bc1b7124f72374ea8556080c2814fc44d9870f33ffbce570e0afe35b65fc19d31152dc88d0b6634e576a1c2eaf164dfe1406840e294e1650648345d1961815704e1c9b3041fcd73179df2c149d7be384aea2211b54066c46f37e65d611e141c1caf5a5fcd1f3603e913bf6c24748482ac587523b694cbeebef28a9bd232ec98aafa84be7ac70acd444c0a64ff21a325e6164a66b2b2661cffd08fce10c5d2686204e645841e66662921002e27675e72bebeb05b9adb7804f125a9cdf243585e6bee1c35d52883a4937997d7be58c2ebf59caa343c1a48fa03643f8b4665af26c722767d61354c1560d14e7b7c7a5b8d79a3481feacabb91f43364ec20ed06996a6d0de13282c6a0755b2e500b19b9cd748396a076123153976478db5c6122a2e9a19459f78c6683c6dd5b3fe84eac096665925472efdf105b9ebaffa9e649b9b5eec6fcc90ca22b9c505577f650b4bdb218a993
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55575);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_xref(name:"IAVT", value:"0001-T-0643");

  script_name(english:"LibreOffice Detection (Mac OS X)");
  script_summary(english:"Gets LibreOffice version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:"The remote Mac OS X host contains an alternative office suite.");
  script_set_attribute(attribute:"description", value:
"LibreOffice is installed on the remote Mac OS X host.

LibreOffice is a free software office suite developed as a fork of
OpenOffice.org.");
  script_set_attribute(attribute:"see_also", value:"http://www.libreoffice.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
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

app = "LibreOffice";

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


kb_base = "MacOSX/LibreOffice";


path = '/Applications/LibreOffice.app';
plist = path + '/Contents/Info.plist';
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' 2>/dev/null | ' +
  'grep -A 1 CFBundleGetInfoString | ' +
  'tail -n 1 | ' +
  'sed \'s/[^0-9.]*\\([0-9.]*\\).*/\\1/g\'';
version = exec_cmd(cmd:cmd);

if (!strlen(version)) exit(0, "LibreOffice does not appear to be installed." + version);

set_kb_item(name:kb_base+"/Installed", value:TRUE);
set_kb_item(name:kb_base+"/Path", value:path);

if (version !~ "^[0-9]") exit(1, "The LibreOffice version does not look valid (" + version + ").");
set_kb_item(name:kb_base+"/Version", value:version);

register_install(
  app_name:app,
  vendor : 'LibreOffice',
  product : 'LibreOffice',
  path:path,
  version:version,
  cpe:"cpe:/a:libreoffice:libreoffice");

report_installs(app_name:app);

