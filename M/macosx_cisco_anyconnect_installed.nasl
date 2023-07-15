#TRUSTED 64f83b4a51dcbb56a342a29ed84bc9ed6f29d9f7367840e7e9e0db236b8550b57611ec3532fd904fec338dc73237f525328e0e40226fdc98be6a22bf457adae9e2982f6cd9e4292c9ba6f1bfb3abef4c9122a3757d5c6f00516460f9137d196fed52a1a7c63c45a5c937221c142a00a34060ce5a2fc4817854800258627c454ecbc8aa6c2f4118265536318b4ed729c3078a3489094dee50de43037e468058c5d010c91c870fdabe8a28a4b197a0ab43e322321036c868718935805858667d3e7e663e15083142c84558de1d1589f10138cbb8410553258fb8894b10e1d21d5629e05e2a5c8266e091c444283e629f6e09e6507399e06b1dad7ffceadb40a9251b1f92d6a764f903c25318c5a2be86cc296a148d643bdd22111f2c7bb0d52663c2db0cff9f0d1562686597445dc26ee6042f32e8ce75b3c58b8bc093d4b722755f24b82f50f84edc022de1a03dd6f68b752a8e64e718610deee591a2a6e402cd39ea66f7f5567f971628ea6de9483bbdbd1d0a05555a6ec4a54c4a9179e995ff8d0a04b8f9fbe3177cc36bd6be040016e0e1e0f46473305b1df7f83eff7b5735c6f47fcdb58dd0c7ef61aa561c969feb382b667ae58cb73ff48745bc6b2bbd8c8b496be98e58f76979e19dfbd197efa9bff6f959433dc456044bb45634f0a4bb33ff4fc004d97a4fbdfc136a45a5bce6ff1882e178f2f63374b38824caa9fac7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59822);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_xref(name:"IAVT", value:"0001-T-0915");

  script_name(english:"MacOSX Cisco AnyConnect Secure Mobility Client Detection");
  script_summary(english:"Checks if the AnyConnect client is installed");

  script_set_attribute(attribute:"synopsis", value:"There is a VPN client installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Cisco AnyConnect Secure Mobility Client (formerly known as Cisco
AnyConnect VPN Client) is installed on the remote host. This software
can be used for secure connectivity.");
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/ps10884/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
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
include("audit.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("install_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");

kb_base = "MacOSX/Cisco_AnyConnect";
appname = "Cisco AnyConnect Secure Mobility Client";

# 3.x check
# Check that the app is really installed
# and grab a detailed version from its
# uninstall app.
path  = '/Applications/Cisco/Cisco AnyConnect Secure Mobility Client.app';
plist = '/Applications/Cisco/Uninstall AnyConnect.app/Contents/Info.plist';

# this works for 3.x >= 3.1.06073
plist_field = 'CFBundleShortVersionString';
cmd = 'if [ `grep ' + plist_field + ' "' + path + '/Contents/Info.plist" 2>/dev/null` ] ; ' +
      'then ' +
        'plutil -convert xml1 -o - \''+plist+'\' | ' +
        'grep -A 1 ' + plist_field + ' | ' +
        'tail -n 1 | ' +
        'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\' ; ' +
      'fi';
version = exec_cmd(cmd:cmd);

# 3.x < 3.1.06073 uses a slightly different plist field
if (isnull(version))
{
  plist_field = 'CFBundleVersion';
  cmd = 'if [ `grep ' + plist_field + ' "' + path + '/Contents/Info.plist" 2>/dev/null` ] ; ' +
      'then ' +
        'plutil -convert xml1 -o - \''+plist+'\' | ' +
        'grep -A 1 ' + plist_field + ' | ' +
        'tail -n 1 | ' +
        'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\' ; ' +
      'fi';
  version = exec_cmd(cmd:cmd);
}

# detect 2.x installs
if(isnull(version))
{
  path = '/Applications/Cisco/Cisco AnyConnect VPN Client.app';
  bin_path = '/opt/cisco/vpn/bin/';
  cmd = bin_path + 'vpn -v | grep "(version" | sed \'s/.*(version \\(.*\\)).*/\\1/g\'';
  version = exec_cmd(cmd:cmd);
}

# And exit if all attempts have failed
if (!strlen(version))
  audit(AUDIT_NOT_INST, appname);

set_kb_item(name:kb_base+"/Installed", value:TRUE);
set_kb_item(name:kb_base+"/Path", value:path);

if (version !~ "^[0-9]") exit(1, "The " + appname + " version does not look valid (" + version + ").");
set_kb_item(name:kb_base+"/Version", value:version);

register_install(
  app_name:appname,
  vendor : 'Cisco',
  product : 'AnyConnect Secure Mobility Client',
  path:path,
  version:version,
  cpe:"cpe:/a:cisco:anyconnect_secure_mobility_client");

report_installs(app_name:appname);

