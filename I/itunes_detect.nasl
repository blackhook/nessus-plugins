#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25996);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_name(english:"Apple iTunes Version Detection (credentialed check)");
  script_summary(english:"Checks the version of iTunes.");

  script_set_attribute(attribute:"synopsis", value:
"Apple iTunes is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"Apple iTunes, a popular media player, is installed on the remote
Windows host.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('install_func.inc');
include('spad_log_func.inc');
include('smb_func.inc');

# Automatically generated from JSON definition using Windows detection Mako template

function detect()
{
  var result = {detected:FALSE, audit:AUDIT_NOT_INST};
  var versions = {};

  var uninstall_path = '', registry_path = '';

  # Uninstall checks
  var uninstall_entry = hotfix_displayname_in_uninstall_key(pattern:'iTunes');
  if (uninstall_entry)
  {
    result = {detected:TRUE};
    spad_log(message:"uninstall entry found: " + uninstall_entry);
    var path_key = str_replace(string:uninstall_entry, find:'DisplayName', replace:"InstallLocation");
    # Registry enumeration plugin populates KB with all Uninstall entries from the registry, so we can grab them directly
    uninstall_path = get_kb_item(path_key);
    if(!empty_or_null(uninstall_path))
    {
      spad_log(message:"uninstall path found: " + uninstall_path);
    }
    else
    {
      uninstall_path = '';
    }

    var version_key = str_replace(string:uninstall_entry, find:'DisplayName', replace:"DisplayVersion");
    # Registry enumeration plugin populates KB with all Uninstall entries from the registry, so we can grab them directly
    var version_string =  get_kb_item(version_key);
    if(!empty_or_null(version_string)) 
    {
      spad_log(message:"uninstall version found: " + version_string);
      versions['uninstall'] = version_string;
    }
  }

  # To prevent issues with connecting to $IPC share we reopen the connection here
  close_registry();
  registry_init();
  var HKLM = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

  # Registry checks
  var value, match;

  var reg_path_sources = ['SOFTWARE\\Classes\\Applications\\iTunes.exe\\shell\\open\\command\\'];
  foreach var reg_path_source (reg_path_sources)
  {

    value = get_registry_value(handle:HKLM, item:reg_path_source);
    #manual edit: this value is a command so we need to fish the path out the rest of it
    match = pregmatch(string: value, pattern: "^.(.*?)iTunes\.exe.+$");
    if (!empty_or_null(match))
    {
      registry_path = match[1];
      spad_log(message:"registry path found: " + registry_path);
      break;
    }
  }

  RegCloseKey(handle:HKLM);
  close_registry(close:FALSE);

  # Path precedence
  var paths = [registry_path, uninstall_path];
  foreach var some_path (paths)
  {
    if(empty_or_null(some_path)) continue;
    path = some_path;
    break;
  }

  # File checks
  var file_ver, error, file_path;
  var exe_found = FALSE;
  var main_path = path;
  var extra_main_path = path;
  var files_to_check = ['iTunes.exe'];
  foreach var file (files_to_check)
  {
    file_path = hotfix_append_path(path:main_path, value:file);
    file_ver = hotfix_get_fversion(path:file_path);

    error = hotfix_handle_error(error_code:file_ver['error'], file:file_path);

    if (error && file_ver['error'] != HCF_NOVER)
    {
      spad_log(message:error);
      continue;
    }
    exe_found = TRUE;

    # No point in saving unknown version
    if(file_ver['error'] == HCF_NOVER) continue;

    versions[file] = file_ver['version'];
    spad_log(message:"file " + file + " version found: " + file_ver['version']);
  }

  if(!exe_found) result = {detected:FALSE, audit:AUDIT_UNINST};
  else result = {detected:TRUE};

  # Version priority
  if(result.detected)
  {
    var precedence = ['iTunes.exe', 'uninstall'];
    foreach var ver (precedence)
    {
      if(empty_or_null(versions[ver])) continue;
      version = versions[ver];
      break;
    }
  }

  return result;
}

##
# Main
##

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app         = 'Apple iTunes';
var cpe         = 'cpe:/a:apple:itunes';
var fa_app_name = 'iTunes';
var extra       = { 'Product' : app };

var version = UNKNOWN_VER;
var path = NULL;

var display_name = hotfix_displayname_in_uninstall_key(pattern:'iTunes');

if (!thorough_tests && !display_name) audit(AUDIT_NOT_INST, app);

hotfix_check_fversion_init();

var result = detect();

hotfix_check_fversion_end();

if (!result.detected) audit(result.audit, app);

#legacy KB items
set_kb_item(name:"SMB/iTunes/Version", value:version);
set_kb_item(name:"SMB/iTunes/Path", value:path);

register_install(
  app_name : app,
  vendor : 'Apple',
  product : 'iTunes',
  path     : path,
  version  : version,
  extra    : extra,
  cpe      : cpe,
  fa_app_name : fa_app_name
);

report_installs(app_name:app);