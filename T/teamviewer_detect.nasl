#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(52715);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"TeamViewer Version Detection");
  script_summary(english:"Checks for TeamViewer");

  script_set_attribute(attribute:"synopsis", value:
"A remote control service is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"TeamViewer, a remote control service, is installed on the remote
Windows host.");
  script_set_attribute(attribute:"see_also", value:"https://www.teamviewer.com/en/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/18");
  
  script_set_attribute(attribute:"cpe", value:"cpe:/a:teamviewer:teamviewer");
  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include("install_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');
var app = 'TeamViewer';
var paths = make_array();
var version = NULL;
var installs = 0;

var port   = kb_smb_transport();
var login  = kb_smb_login();
var pass   = kb_smb_password();
var domain = kb_smb_domain();

registry_init();
var hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
# Modern versions do not support multiple installs
# Use version info from registry and fall back onto product version from exe if necessary.
# x64 pkg installs to HKLM\SOFTWARE\TeamViewer\, x86 pkgs to HKLM\SOFTWARE\WOW6432Node\TeamViewer\ 
var key, path;
var key_values = [
  "SOFTWARE\TeamViewer\",
  "SOFTWARE\WOW6432Node\TeamViewer\"
];
foreach key (key_values){
  var key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!empty_or_null(key_h)){
    path = RegQueryValue(handle:key_h, item:"InstallationDirectory");
    version = RegQueryValue(handle:key_h, item:"Version");   
  }
  if (!empty_or_null(path)){
    if(!empty_or_null(version)) paths[path[1]] = version[1];
    else paths[path[1]] = NULL;
    installs++;
  }
}

# Older versions use a Version# subkey, and may have multiple installs
var i, subkey, pat, key2, key2_h, value, value_ver;
var info = RegQueryInfoKey(handle:key_h);
for (i = 0; i < info[1]; ++i)
{
  subkey = RegEnumKey(handle:key_h, index:i);
  pat = '^Version[0-9\\.]+';

  if (strlen(subkey) && preg(pattern:pat, string:subkey))
  {
    key2 = key + '\\' + subkey;
    key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
    if (!isnull(key2_h))
    {
      value = RegQueryValue(handle:key2_h, item:"InstallationDirectory");
      value_ver = RegQueryValue(handle:key2_h, item:"Version");
      if (!empty_or_null(value[1]))
      {
        if(!empty_or_null(value_ver[1])) paths[value[1]] = value_ver[1];
        else paths[value[1]] = NULL;
        installs++;
      }
      RegCloseKey(handle:key2_h);
    }
  }
}

RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

if (!installs) audit(AUDIT_NOT_INST, app);

var exe, bin_installed, err;
foreach path (keys(paths))
{
  if(isnull(paths[path]))
  {
    exe = hotfix_append_path(path:path, value:"TeamViewer.exe");
    bin_installed = hotfix_file_exists(path:exe);
    if ( empty_or_null(bin_installed) || !bin_installed ) continue;

    version = hotfix_get_pversion(path:exe);

    err = hotfix_handle_error(
      error_code  : version['error'],
      file        : exe,
      appname     : app,
      exit_on_fail: TRUE
    );
    version = join(version['value'], sep:'.');
  }
  else
    version = paths[path];

  if(isnull(version)) version = UNKNOWN_VER;
  # 11.x is known to have junk in the Version registry data, e.g., extra spaces or text
  else version = preg_replace(string:version, pattern:"^([0-9.]+).*$", replace:"\1");
  set_kb_item(name:"SMB/TeamViewer/"+version, value:path);

  register_install(
    vendor:"TeamViewer",
    product:"TeamViewer",
    app_name:app,
    path:path,
    version:version,
    cpe:"cpe:/a:teamviewer:teamviewer"
  );

}

hotfix_check_fversion_end();

set_kb_item(name:"SMB/TeamViewer/Installed", value:"TRUE");

report_installs(app_name:app);
