#TRUSTED 2e13d61b255d68b409e2849c9ede0e552d5ffa09c6b05277ff132d178ec64f23804b76c3c7cf7b36e0e52cc605d647ac831ea7922b3840d23ad6e1ea66d6f08109b71cee3454643c4b9716d778541bf1758584b916468c5b718aa804c8aa1ffed26e468b1b3106397022beb865c60610d7b752a1bd90a4715daa205e2e56f007ec421e4bd9fe0bedd11797aa26fb1cff547381f739006c33a2afa0c49af2e3ed70edf1a5f2ce63ac52d73fc662e8f0fd0ee29a206e2beb042963750d8d29cf36d5078ba628c108d6c0c0f54b4628ec31fedfea0f046f6e9e087733efc2ca5dcc7420f4c0294f125f578c11233f51941f7d604547540d516b902db92acad0125c1535f9e9a84936e9141e3220761e8f7adf1c73ab823274edc60a2950b8d9d29ff24048b094cf0439d1389cbbe4034eb8cef98eaa0db2a4a7c34296ce1a5bd7ef5657dd08a112931b08c615ec018203c547a3d4277c6ce186078013cf96e83a72b33d28c7dd214f2a829d818f8daa20fe9cbbbbc879cd8a41057191f0ca6a08a70cc87da2053ec22dc3cf49d0878df5290c2c14c59e61b65540243dc473463843d2c89b66c4935430fe857afed65affd39f04940fc48d32c1d1d0ddca52d03a3f23d99278d2af79faf626c13cce4c2aa441b0fb2cb501742ebf1f5d76301f01fbf1a79294d479ca984239cba3d51b7d888eaf9567bafd6ab668991ab7c42107af
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65924);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_name(english:"Google Picasa Installed (Mac OS X)");
  script_summary(english:"Gets Google Picasa version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:"Google Picasa is installed on the remote Mac OS X host.");
  script_set_attribute(attribute:"description", value:"Google Picasa is installed on the remote Mac OS X host.");
  script_set_attribute(attribute:"see_also", value:"http://www.google.com/picasa/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:picasa");
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


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

appname = "Google Picasa";
kb_base = "MacOSX/Picasa";

path = '/Applications/Picasa.app';
plist = path + '/Contents/Info.plist';
cmd = 'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);

if (!version)
{
  cmd = 'cat \'' + plist + '\' | ' +
    'grep -A 1 CFBundleShortVersionString | ' +
    'tail -n 1 | ' +
    'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
  version = exec_cmd(cmd:cmd);
}

if (!strlen(version)) audit(AUDIT_NOT_INST, appname);

if (version !~ "^[0-9][0-9.]+$") audit(AUDIT_VER_FAIL, appname);

set_kb_item(name:kb_base+"/Installed", value:TRUE);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

version_ui = ver[0] + "." + ver[1] + " Build " + ver[2] + "." + ver[3];

set_kb_item(name:kb_base+"/Version", value:version);
set_kb_item(name:kb_base+"/Version_UI", value:version_ui);
set_kb_item(name:kb_base+"/Path", value:path);

register_install(
  app_name:appname,
  vendor : 'Google',
  product : 'Picasa',
  path:path,
  version:version,
  display_version:version_ui,
  cpe:"cpe:/a:google:picasa");

report_installs(app_name:appname);

