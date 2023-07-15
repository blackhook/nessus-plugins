#TRUSTED b0250040a4bb80ca6b5323155ccbadb0f2ca9e619950021812c7e4c36469c0ed7e430db68ecaba44e50553ac60de438c9ca5e0d7fdb7086d8c0e9b6e8e16980a33be69404fc65889fc998353e3cf8e302c5e34a2eb2061acad37644a48dad644b8ed63778754c8018e58057607b0704424f8df01db8c5c1418608ee2a99b47b33319aa3aff1dceb884db25c28ae344163e989106c208262cf5289798429fdeb714751574ae2269b536b8cc0df88b88163fdc3e31f34eb4877bc23eb59dbe24126dc5d50b3695d7a565804483ed7d5ec22348249f40dd490824e4a8ee5d4c91881cb8c0cd197889f92376ea9ba941a214316a1116ceb196d66f2dce133a1acc9d578bd3d6608a07323a26ad8db384581ea4a5d279f6472d9cdd0d9b72e019dd9d9af06f2f9cc4d109315ad5422ef1c31848cb0ec06d7300dcc960179bee48248481be4bbd0ae1ea5cfda1d0637313ab49b891630947d45a22db7dc0617a11a1e9971c286a3481a6c4c8b7d1020ce228a0029cb9f72f5478d064ea423fb81d91881dcb7264a5e0d90333feb1abb74de323ad7629f2544a99c9e67f7e5cfc9a781072314b64e0ed65cc451609e78496175de2b691ebcd53d468e421067dc03737058856cb5238980d57727ff04b5ca6940c805675bb3f1f16dbf6779508596f73fd9ad91b5fde2d0afbc3aeebffdf5058cc01dbcce54b7b1d2610af4611719ae3c3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61412);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_name(english:"Apple Xcode IDE Detection (Mac OS X)");
  script_summary(english:"Detects Apple's Xcode IDE.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an integrated development environment installed.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has Apple Xcode installed. Xcode is a
development environment for creating applications that will run on
Apple products.");
  script_set_attribute(attribute:"see_also", value:"https://developer.apple.com/xcode/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:xcode");
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
if (!os) audit(AUDIT_HOST_NOT, "running Mac OS X");

appname = 'Apple Xcode';

kb_base = "MacOSX/Xcode/";

# some default directories Xcode may be installed into
xcode_pathlist = make_list('/Applications/Xcode.app/Contents/Developer',
                           '/Applications/Xcode.app',
                           '/Developer/Applications/Xcode.app/Contents/Developer',
                           '/Developer/Applications/Xcode.app',
                           '/Developer');

xcode_b_pathlist = make_list('/Applications/Xcode-Beta.app/Contents/Developer',
                             '/Applications/Xcode-Beta.app',
                             '/Developer/Applications/Xcode-Beta.app/Contents/Developer',
                             '/Developer/Applications/Xcode-Beta.app');

# get path of current Xcode install being used (if possible)
# and add it to the path list
# this command first appeared in Xcode 3.0
cmd = 'xcode-select -print-path';

xcode_path = exec_cmd(cmd:cmd);

if (
  'Error: No Xcode is selected' >!< xcode_path &&
  xcode_path[0] == '/' && # valid paths should start with /
  !isnull(xcode_path)
) xcode_pathlist = make_list(xcode_pathlist, xcode_path);

xcode_pathlist = list_uniq(xcode_pathlist);
install_num = 0;
report = '';

foreach path (xcode_pathlist)
{
  xcode_build = path + '/usr/bin/xcodebuild';
  command_result = exec_cmd(cmd:xcode_build + ' -version');
  if (isnull(command_result) ||'Xcode' >!< command_result) continue;

  cmd = xcode_build + ' -version | head -1 |' +
        'sed \'s/.*Xcode \\(.*\\)/\\1/g\'';

  version = exec_cmd(cmd:cmd);

  item = eregmatch(pattern:"^[0-9\.]+$", string:version);
  if (isnull(item)) continue;

  set_kb_item(name:kb_base+install_num+'/Path', value:path);
  set_kb_item(name:kb_base+install_num+'/Version', value:version);

  register_install(
    app_name:appname,
    vendor : 'Apple',
    product : 'Xcode',
    path:path,
    version:version,
    cpe:"cpe:/a:apple:xcode");

  report += '\n  Path    : ' + path +
            '\n  Version : ' + version +
            '\n';
  install_num ++;
}

foreach path (xcode_b_pathlist)
{
  xcode_build = path + '/usr/bin/xcodebuild';
  command_result = exec_cmd(cmd:xcode_build + ' -version');
  if (isnull(command_result) ||'Xcode' >!< command_result) continue;

  cmd = xcode_build + ' -version | head -1 |' +
        'sed \'s/.*Xcode \\(.*\\)/\\1/g\'';

  version = exec_cmd(cmd:cmd);

  item = eregmatch(pattern:"^[0-9\.]+$", string:version);
  if (isnull(item)) continue;

  set_kb_item(name:kb_base+install_num+'/Path', value:path);
  set_kb_item(name:kb_base+install_num+'/Version', value:version);

  register_install(
    app_name:appname+'-Beta',
    vendor : 'Apple',
    product : 'Xcode',
    sw_edition : 'Beta',
    path:path,
    version:version,
    cpe:"cpe-x:/a:apple:xcode_beta");

  report_b += '\n  Beta path    : ' + path +
              '\n  Beta version : ' + version +
              '\n';
  install_num ++;
}

if (report)
{
  set_kb_item(name:kb_base+'NumInstalled', value:install_num);
  set_kb_item(name:kb_base+'Installed', value:TRUE);

  if(!empty_or_null(report_b))
    report += report_b;

  security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
}
else audit(AUDIT_NOT_INST, appname);
