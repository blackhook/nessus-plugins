#TRUSTED a08e369d4dc7bc17ae3ef5db4a2d828270b8d3c4eddc0524fae031c3f2fa2d741b86201f2d62d5a02683de717ecef211edc8d12d16788f792ec6c9aee3b84163e4133eae6a5232e1e99ee53a4a1767ce86beb0dcd216d31431cb0587169ce4e170e122ae1df8477747a46486a0b133f995bf1b065ff63138f8b1b77e279f0e61f569e88358a639793e8121d9af9375bc1bc8fdc55329b54d603cb4cc8ad110911c1e88975ee15d62dbecca9cdcad9d6fc979c4de38005359e4dddf8667c7ace265ee4a9d83c90a79871b687ecef0de19559809ed19fd27d3e05f24452f9f11fde73e7e889b3fda0559d7c57328a76bcc269095909e4439c1638b5ec41227bbd3151dbea35886132c47581275b010021b54934fa3b2b3e69997531a38f2be5357cced65fe2121f68624691aff5b31ec9d514a3f07e1a7a58b90a6ef9bd22f89e669fe938c6efba12efe2ecbc4d35ec5ab8c378cf0d11ede79e0c348cb4eee88b293bb73d489024af87cf08928b1923725d122d52bde5db69aabe7dfa18b8e70b7d0ad155e67cce05b60aca7008725e0e9208ea28415b7dc494c23e287d939d8d1d4fb589d6e366fe6072b339ddb17f8eb6a9cbfda9c6b63acb78f4355deb02f80642c4cecdef9227659ca2add5134046447a4ece166a55379e9e7ebc9df93071fb650927ae1666a6e1d0c2448f50b6db908c5f511d3ea2c478a2d6c0026e37acb
#TRUST-RSA-SHA256 33527777bd88cbae9fc13145866083e3a85eb97fce24a5d82bea92d0e1d073146cb9502462cee63aa9aab486656eeb7c34c4bf4f32adc19551b1d57cd4e90e408c0d707cff950bdca402477889b913a5f3a994beb2cd010548e7053009ca28eedf67be86de1d04b0f0230606d64c06aef3cfbfaf621b3c2871d7562b8772cb49b5b636988fbb38e20d1da4f3fc3f1dca5195724b1be9b7332db108c5839f061bf166984495d03449a1506dd54d0f51cf2355e2eb98931ff654afb8c0a09ffa32a1e91ba7047821fce05efcc74558af3d115ba5b7bdbbc40777ee8e46a8cb3e79e7911431fe0e68be98741abc2fb056865ae4006a1cf77fdcd90426d38a704b039f275f8b5bc6aef46f5388507ccac9316e9598dd7405393175533564132ba5772bb348149fa9104ed2a45ba962b91065a40c21d87c21ef522e2b43108843841576206802efafc7007c0490f8ba5dc16cbe3527d1735a610af7371947b9a8c08b02a39c6947f01ee8791fbe53fcf277fcf91993312aece9617dca0943e1ed9f1066f2002a2d9e7925629e3c9373e54b14b4dea412d97eab20491be2e4f817c1a8e4f0304ad24d086e5829490ce97b77aa91a82dbd76754db278526b8728a19c054866d63536323a0e5294aacede83c9d9e5e0813614f381ac4a472bd8bc94483ffe413e307a9e6f6db2d4a720f088b520ec4966f0e0461829cb3a68490d580896
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55420);
  script_version("1.37");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/20");

  script_xref(name:"IAVT", value:"0001-T-0524");

  script_name(english:"Adobe Reader Installed (Mac OS X)");
  script_summary(english:"Gets the Reader version from Info.plist.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a PDF file viewer.");
  script_set_attribute(attribute:"description", value:
"Adobe Reader, a PDF file viewer, is installed on the remote Mac OS X
host.");
  script_set_attribute(attribute:"see_also", value:"https://acrobat.adobe.com/us/en/products/pdf-reader.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "command_builder_init.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("macosx_func.inc");
include("install_func.inc");
include('find_cmd.inc');

function adobe_extract_version_track(plist)
{
  local_var result = [];

  local_var version_cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
    'grep -A 1 CFBundleShortVersionString | ' +
    'tail -n 1 | ' +
    'sed \'s/.*<string>\\(.*\\)<\\/string>.*/\\1/g\'';

  result[0] = exec_cmd(cmd:version_cmd);

  local_var track_cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
    'grep -A 1 TrackName | ' +
    'tail -n 1 | ' +
    'sed \'s/.*<string>\\(.*\\)<\\/string>.*/\\1/g\'';

  result[1] = exec_cmd(cmd:track_cmd);

  return result;
}

## Main ##

var app = "Adobe Reader";

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_HOST_NOT, "Mac OS X");

var kb_base = "MacOSX/Adobe_Reader";

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

var item, tmp, dir, base_dir, plist, timeout, result, version, track, cmd;

var adobe_path_patterns = make_list('*Adobe*Reader*.app', '*Acrobat*Reader*.app', '*Adobe*Acrobat*Reader*.app');

var dirs = find_cmd(
    path_patterns:adobe_path_patterns,
    start:'/Applications',
    timeout:240,
    maxdepth:1,
    sanitize_result:TRUE
  );

if (info_t == INFO_SSH) ssh_close_connection();

if (empty_or_null(dirs)) audit(AUDIT_NOT_INST, app);
else if(dirs[0] == FIND_OK ) dirs = dirs[1];

var install_count = 0;

foreach dir (split(dirs, keep:FALSE))
{
  ## skip any other variant that doesn't match
  if (!pregmatch(string:dir, pattern:"(Adobe\sAcrobat\sReader*|Adobe\sReader*|Acrobat\sReader*)"))
    audit(AUDIT_NOT_INST, app);

  base_dir = dir - "/Applications";

  plist = dir + "/Contents/Info-macos.plist";

  result = adobe_extract_version_track(plist:plist);
  if (empty_or_null(result[0]))
  {
    plist = dir + "/Contents/Info.plist";
    result = adobe_extract_version_track(plist:plist);
  }

  version = result[0];
  track = result[1];

  if (isnull(version) || version !~ "^[0-9]+\.") version = UNKNOWN_VER;
  if (isnull(track)) track = UNKNOWN_VER;

  set_kb_item(name:kb_base+base_dir+"/Version", value:version);
  set_kb_item(name:kb_base+base_dir+"/Track", value:track);

  register_install(
    app_name:app,
    vendor : 'Adobe',
    product : 'Acrobat Reader',
    path:dir,
    version:version,
    display_version:version,
    cpe:"cpe:/a:adobe:acrobat_reader");

  install_count += 1;
}

if (install_count)
{
  set_kb_item(name:kb_base+"/Installed", value:TRUE);
  report_installs(app_name:app, port:0);
}
else audit(AUDIT_UNKNOWN_APP_VER, app);
