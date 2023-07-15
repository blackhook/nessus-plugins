#TRUSTED 6eb2cd64dd0c670880094060bbaab2c8f84cec326ca65b37cf91ab80a04c8fc807a999c4f0a9c79053036dfc71b1a2ef521e98b4d6b4dd6620538c7fda84fa648a70d4c39b2c06949f48a4c0638c04dcbe6bd5157d6d770124ced91ec4f4171e30c675b7227f7d570dfae8201174ad20bbfc3a90bbfb8d64b46ddb758c2acac984093f1aff8937b46dd354b79dca9e2551b7ec65bb2927b971cb28e9838cff58c7ba22dec1059ecf7b41032d594e822272dce1592ed49275703e8adbfea9776bcf4e2afef680315ca6e58d4b1c408744b3ffee5d4b49f608f7b548273b2070646bd05993551b0ee2ab33642894b5abeec4b9937592e11d62543687a90988ab566f231484bd5e2c340d74551bf1b8edce029ece6e54ed6a3b198f7ea332ef55eca628fefc49daae082659b39e186d998c364367a03463c088e2159f7237481fd81e594d0b6b0bcb9a281c8caa08a446a7361b2a97bc63c5ead3a7aef34589f4ccd817856df5f3407ef722b8e412345e05c6e4cdf52425da4eaf1d0dc619e426ccb326512c5ed0ac024eeaaea7049dd1761bb73b9ccae2b9bd2a165e8a77f53a838caa06bd5abd5897005750897e9b7675001fcd8dddf99ed7bba7ff7c14032f5555929b24f85908f8f4426b7e93f47d2fc655b91c1a56e974a931c4e8f8ed9f18567ff7a3d5d5d7541297d52a6b3b8efdfe18634efabe15e65cd9c94cc8d1e82c
#TRUST-RSA-SHA256 7a0cb10878b8bbc6f0937127ae9616ecdff0d77e3388594329485bf6b9dc245818bfe6545866653f1aca320b1c986e288f3735527bdee4e1fb520dd9f8834ccffbaf405cf5e2d260ee7e859bdbabc59f7b90ee8de82bce1531ac886843447882a78ccde572dbe4a811f051d0e52861984de2de6efc67a397d84a936e37ca97cc9a10dc7e6e6f3326daf83566209cf6951a810eabe0950e0cce37cfa202be5af58d52a1c6c71453823879e88f614340269692780e79897f18abdea1ab1c55a4722b6ef6b379e055a108cffd955939457818c5acac73ce82831a25248f0a3fd0fbd2aa3d6da6e035f8e2c36814e5833f05175e744f5387a18ec8b57d2b997b8b7e47dbe28e051426e6e29d8f24c6fa60c28f1d817a78ac45183463b879002c49c7cd17943dc1e19457f299b6688fe3bc51666fa08cce5d3f0cef83457cff625fb12da5c2f6c1782e1e9e4f6cee5a2a678dcdb61da9082be03b1ffd0209140bd8027126e702c6b1523d8a5b989a42f95f53b86a19f213ba111c10c881ad094e962406f33c844affc0479bb35b7f3a2ff7fb4893679b23471c4d3f1c3e55ec071f61d470b0b628f422fae1d92a2cf508d8c711a7849bd0b1552bc1f87f392156f87d18c79e2eb8d4e701b80c955f171383495b7ffd3ba385c73fd23f101abe1cbbe411d74b0c483fb93432a2cbf3825aba55443bd1133ea1046e2f9553404a46357e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(59177);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"Adobe Flash Professional for Mac Installed");
  script_summary(english:"Gets Adobe Flash Professional version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:"The remote Mac OS X host contains a multimedia authoring application.");
  script_set_attribute(attribute:"description", value:
"Adobe Flash Professional for Mac, a multimedia authoring application,
is installed on the remote Mac OS X host.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/flash.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_cs");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "command_builder_init.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('ssh_func.inc');
include('telnet_func.inc');
include('hostlevel_funcs.inc');
include('macosx_func.inc');
include("install_func.inc");
include('sh_commands_find.inc');

app = 'Adobe Flash Professional';

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item('Host/local_checks_enabled')) exit(0, 'Local checks are not enabled.');
packages = get_kb_item_or_exit('Host/MacOSX/packages');
kb_base = 'MacOSX/Adobe Flash Professional';

if (islocalhost())
{
  if (!defined_func("pread")) audit(AUDIT_FN_UNDEF,"pread");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  info_t = INFO_SSH;
}

# Get a list of install directories, given that multiple versions can be installed
err = '';
dirs = sh_commands::find('/Applications', '-xautofs', '-tenb_fstype_exclusions', '-tenb_path_exclusions', '-name', 'Adobe Flash CS*', '-mindepth', '1', '-maxdepth', '1', '-type', 'd');
if (dirs[0] == sh_commands::CMD_OK)
{
  dirs = dirs[1];
}
else if (dirs[0] == sh_commands::CMD_TIMEOUT)
{
  err = 'Find command timed out.';
}
else
{
  err = dirs[1];
}

if (info_t == INFO_SSH) ssh_close_connection();

if (!empty_or_null(err)) exit(1, err);

if (empty_or_null(dirs)) audit(AUDIT_NOT_INST, app);

install_count = 0;
foreach dir (split(dirs, keep:FALSE))
{
  base_dir = (dir - '/Applications') + '.app';

  plist = dir + base_dir + '/Contents/Info.plist';

  cmd =
    'plutil -convert xml1 -o - \'' + plist + '\' 2>/dev/null | ' +
    'grep -A 1 CFBundleShortVersionString | ' +
    'tail -n 1 | ' +
    'sed \'s/.*<string>\\(.*\\)<\\/string>.*/\\1/g\'';
  version = exec_cmd(cmd:cmd);
  if (isnull(version) || version !~ '^[0-9\\.]+') version = 'n/a';

  if (!isnull(version) && version =~ '^[0-9\\.]+')
  {
    set_kb_item(name:kb_base+base_dir+'/Version', value:version);
  }

  register_install(
    vendor:"Adobe",
    product:"Flash",
    app_name:app,
    path:dir,
    version:version,
    cpe:"cpe:/a:adobe:flash");

  install_count += 1;
}

if (install_count)
{
  set_kb_item(name:kb_base + '/Installed', value:TRUE);
  report_installs(app_name:app, port:0);
}
else exit(1, 'Failed to extract the installed version of Adobe Flash Professional.');
