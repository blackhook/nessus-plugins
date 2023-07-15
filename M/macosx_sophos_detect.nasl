#TRUSTED ad635df6c747379ac94013a2ec3a9e722da0a76487af79164c77f8720b2edf6af269b7a70402fa4cac05ef9e37ed58228545130190ff3f7706ac07ff3c638bb7dd273c50dc89ece5c8cfc739e84fa1b71f309f11eddae85edbfc016627d4bc5ef2676dec48fb33370b28347c45e5a96efb3c84b8042d978b1695746e116578faf94c17746f3142a5d457323d011958088b0b3e21412877bbde489fd84cd1ee309d06149556a2943a195722ef93805eb6264827ed6ca2051c1205ca962fa9d2238e725390afc7d2ee74dcc8ce98e85063d30130d5a99c3fad38b65ff6d96e880de2fb6512e1bafd46f9ff90a7b3f2135fbc280b07cc47236f09b907a4dcad1fe8de2dbf5d2367a96bf9b1a71ad9b49754a7686663ceae06327722703ef59be8c20d7202d969517fe7484c778c381991c2da3a451c73c8da1301221b43dbd93c3874f85d3f086c82a21e2cdc91e95a92f47f7dcf4e0b95c4bc19d91639de1f484be42af61436e0848e7acaa7d3e76eeb9f6bc50dfd77f9a35f10c95546761016933552fb342fad66f6033c6c6b8a9580c8264f56b2797017b7d1fab1a9abc64db8f3d5e2bcfb1387d35a8652ee0ca86755627c6080054230ecac288b9249045937265d7f90a1306d26dfd6872ed8385a321ea22b3d02f4505cf0a79fa08c7a66bdeea1f73a82699d8c94773c860e499059d03ff1d6644006252fcadf3aa1cbfd17
#TRUST-RSA-SHA256 a05c55f7bd29ed6fd45bbd7784f6a6cd92861a560e24fc52ff4023763fde45e029de76b3db66dd395a37898fbc24e19ff7ede1236e89b5ef64977503b209fe2a82c37486b50a673b277eb7fec2782a20ed01c684775c978f0176fc7a8e5374ac41254e6259210e3924e687f7b13571f738aec8a9b9efff5f93bfc5b5d94c8768aee704daec03fdb549f6c6ca1675f634577ba9a76e5043f8757ecd93bd3b64c04c4a7fe3cc99d099d6e9d8e60cc7a1216c3c1f5294b6f2a6cc7aaa9662193a21b6544f71b9481834d34de9c8994e2fa05cc517617432a60bfa9d4af8e01a99d57a15cf462619351e1ceb520548140164f36bc0d908a39c5c36f2b98cd400d3660ac821c09fb5c15a2c627186eaa87b44c4c4acc36ee7e0b24ebf601fb0550c37b95d3857647eacfbf459ae935ca24ea5bda779a2ec5a8d44aafc71008f34a4a70b3f047df10c3078901df055f62e441ec6e982063c342b7c621d3987e0f4858420645200030e17f1b3a5f97075e11c4aa03e9820ea925a870383bc3d75b3fcf9210128ee6c96251a801d4e2e9b02caa062b3ff2392dd5f1a600a50a410eba02e3df1e7f2c43cc7aee75e822981599c2ffd203d654e97d30363debcdf47779acc6b1450c3e353f985d826329f8adab46864635252b1fc0e84df686afed4e8636a6fa1616370289262b86b87fc30f3e0a994197785497fb15ed93de476a005f8da
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54845);
  script_version("1.39");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_name(english:"Sophos Anti-Virus for Mac OS X Detection");
  script_summary(english:"Checks for Sophos Anti-Virus.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote Mac OS X host.");
  script_set_attribute(attribute:"description", value:
"Sophos Anti-Virus for Mac OS X, a commercial antivirus software
package, is installed on the remote host. Note that this plugin only
gathers information about the software, if it's installed. By itself,
it does not perform any security checks and does not issue a report.");
  script_set_attribute(attribute:"see_also", value:"https://www.sophos.com/en-us.aspx");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sophos:sophos_anti-virus");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"asset_categories", value:"security_control");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}

include("audit.inc");
include("datetime.inc");
include("global_settings.inc");
include("install_func.inc");
include("macosx_func.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("security_controls.inc");

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

var app = "Sophos Anti-Virus";
var cpe = "cpe:/a:sophos:sophos_anti-virus";
var plist = NULL;
var regex = NULL;
var sweep = "/usr/local/bin/sweep -v";
var plutil = "plutil -convert xml1 -o - ";
var sophos_product = "Anti-Virus"; # by default

 # Sophos v10.x for Mac:
 # Endpoint: /Applications/Sophos/Sophos Endpoint.app/Contents/Info.plist
var products = make_array(
          'Anti-Virus', make_list('/Applications/Sophos Anti-Virus.app/Contents/Info.plist'),
          'Home', make_list('/Applications/Sophos Home.app/Contents/Info.plist'),
          'Endpoint', make_list('/Applications/Sophos Endpoint.app/Contents/Info.plist',
                                '/Applications/Sophos/Sophos Endpoint.app/Contents/Info.plist'));

var paths = make_array(
          '/Library/Sophos Anti-Virus/product-info.plist', 'ProductVersion'
      );

var order = make_list(
          '/Library/Sophos Anti-Virus/product-info.plist'
      );

var flav;

foreach flav (keys(products))
{
  dbg::log(src:SCRIPT_NAME, msg:"Checking product "+flav);
  flav_paths = products[flav];
  foreach flav_path (flav_paths)
  {
    found = exec_cmd(cmd:'plutil \"' + flav_path + '\"');
    if (!isnull(found) &&
        "file does not exist" >!< found)
    {
      sophos_product = flav;
      paths[flav_path] = 'CFBundleShortVersionString';
      # adding the element regex for that file
      append_element(var:order, value:flav_path);
      if (flav == 'Home')
      {
        # look for HomeVersion in this case
        paths['/Library/Sophos Anti-Virus/product-info.plist'] = 'HomeVersion';
      }
      break;
    }
  }
}

var path;

foreach path (order)
{
  found = exec_cmd(cmd:'plutil \"' + path + '\"');
  if (!isnull(found) &&
      "file does not exist" >!< found)
  {
    plist = path;
    regex = paths[path];
    break;
  }
}

if ("Info.plist" >< path)
  sweep = "/usr/bin/sweep -v";

if (isnull(plist))
  audit(AUDIT_NOT_INST, "Sophos Anti-Virus");

cmd1 = plutil + "'" + plist + "' | "
     + "grep -A 1 " + regex + "| "
     + "tail -n 1 | "
     + 'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';

# This value will return a string in format HH:MM:SS DD MON YYYY
av_log = "/Library/Logs/Sophos Anti-Virus.log";
cmd2 = "cat '" + av_log + "' | "
     + "grep up-to-date | "
     + "tail -n 1 | "
     + 'sed -e \'s/.*Software is up-to-date at //\'';

vvf = "/Library/Sophos Anti-Virus/VDL/vvf.xml";
cmd3 = "cat '" + vvf + "' | "
     + "grep VirusData | " 
     + 'sed -e \'s/.*VirusData Version="//\' -e \'s/"//\' -e \'s/ .*//\'';

//cmd4 = "ps aux | grep -e 'SophosUpdater' | grep -v 'grep'";

cmd4 = "ps aux | grep -e 'SophosUpdater|SophosAutoUpdate' | grep -v 'grep'";

cmd5 = "ps aux | grep -e 'SophosAntiVirus' | grep -v 'grep'";

cmd6 = sweep + " | grep 'Engine version'";

results = exec_cmds(cmds:make_list(cmd1, cmd2, cmd3, cmd4, cmd5, cmd6));


if (isnull(results))
  audit(AUDIT_UNKNOWN_APP_VER, "Sophos Anti-Virus");

sophos_product_version = results[cmd1];

# If the version is <9, we don't have the signature date. <9 is unsupported.
if (sophos_product_version =~ "^[0-8]\.")
  sophos_threat_data = UNKNOWN_VER;
else
  sophos_threat_data = results[cmd3];

sophos_engine_version = split(results[cmd6], sep:":");
if (!empty_or_null(sophos_engine_version[1]))
  sophos_engine_version = strip(sophos_engine_version[1]);
else
 sophos_engine_version = UNKNOWN_VER;

sophos_auto_update_running = results[cmd4];
sophos_antivirus_running = results[cmd5];

date_match = pregmatch(string:results[cmd2], pattern:"^\d\d:\d\d:\d\d (\d+)\s+([A-Za-z]+)\s+(\d+)$");
if (!isnull(date_match))
{
  day = date_match[1];
  month = month_num_by_name(date_match[2], base:1);
  if (!isnull(month) && int(month) < 10)
    month = "0" + month;
  year = date_match[3];
  if (!isnull(year) && !isnull(month) && !isnull(day))
  {
    sophos_last_update_date = year + "-" + month + "-" + day;
  }
}

if (isnull(sophos_product_version) || isnull(sophos_threat_data))
  audit(AUDIT_UNKNOWN_APP_VER, "Sophos Anti-Virus");

if (isnull(sophos_engine_version))
  sophos_engine_version = 0;

pattern = "^[0-9][0-9.]+$";

if (sophos_product_version !~ pattern)
  audit(AUDIT_UNKNOWN_APP_VER, "the Sophos Anti-Virus product");

if (sophos_threat_data !~ pattern && sophos_product_version !~ "^[0-8]\.")
  audit(AUDIT_UNKNOWN_APP_VER, "the Sophos Anti-Virus threat data");

if (sophos_engine_version !~ pattern)
  audit(AUDIT_UNKNOWN_APP_VER, "the Sophos Anti-Virus engine");

date_pattern = "^\d{4}-\d{2}-\d{2}$";

if (sophos_last_update_date !~ date_pattern)
  sophos_last_update_date = "Unknown";

set_kb_item(name:"Antivirus/SophosOSX/installed", value:TRUE);
set_kb_item(name:"MacOSX/Sophos/Path", value:path);
set_kb_item(name:"MacOSX/Sophos/Product", value:sophos_product);
set_kb_item(name:"MacOSX/Sophos/Version", value:sophos_product_version);
set_kb_item(name:"MacOSX/Sophos/ThreatDataVersion", value:sophos_threat_data);
set_kb_item(name:"MacOSX/Sophos/EngineVersion", value:sophos_engine_version);
set_kb_item(name:"MacOSX/Sophos/LastUpdateDate", value:sophos_last_update_date);

extra_info = make_array(
    "ThreatDataVersion", sophos_threat_data,
    "EngineVersion", sophos_engine_version,
    "AutoUpdateRunning", sophos_auto_update_running,
    "AntiVirusRunning", sophos_antivirus_running,
    "LastUpdateDate", sophos_last_update_date);

if ("SophosUpdater -d" >< sophos_auto_update_running)
{
  extra_info['AutoUpdateRunning'] = 'on';
  set_kb_item(name:"MacOSX/Sophos/AutoUpdateRunning", value:TRUE);
}
else
{
  extra_info['AutoUpdateRunning'] = 'off';
  set_kb_item(name:"MacOSX/Sophos/AutoUpdateRunning", value:FALSE);
}

if ("SophosAntiVirus -d" >< sophos_antivirus_running)
{
  extra_info["AntiVirusRunning"] = 'on';
  set_kb_item(name:"MacOSX/Sophos/AntiVirusRunning", value:TRUE);
}
else
{
  extra_info["AntiVirusRunning"] = 'off';
  set_kb_item(name:"MacOSX/Sophos/AntiVirusRunning", value:FALSE);
}

extra_info['Product'] = sophos_product;

register_install(
  vendor:"Sophos",
  product:"Sophos Anti-Virus",
  app_name:app,
  path:path,
  version:sophos_product_version,
  extra:extra_info,
  cpe: cpe
 );

var autoupdate_string = "yes";
if(!sophos_auto_update_running) autoupdate_string = "no";

var running_string = "yes";
if(!sophos_antivirus_running) running_string = "no";

security_controls::endpoint::register(
  subtype                : 'EPP',
  vendor                 : "Sophos",
  product                : app,
  product_version        : sophos_product_version,
  cpe                    : cpe,
  path                   : path,
  running                : running_string,
  signature_version      : sophos_threat_data,
  signature_install_date : sophos_last_update_date,
  signature_autoupdate   : autoupdate_string
);

report_installs(app_name:app);
