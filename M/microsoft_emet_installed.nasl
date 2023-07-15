##
# (C) Tenable, Inc.
##

include("compat.inc");

if (description)
{
  script_id(49675);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/04");

  script_name(english:"Microsoft Enhanced Mitigation Experience Toolkit (EMET) Installed");

  script_set_attribute(attribute:"synopsis", value:
"A tool for mitigating security vulnerabilities is installed on the
remote system.");
  script_set_attribute(attribute:"description", value:
"Microsoft's Enhanced Mitigation Experience Toolkit (EMET), a tool for
mitigating security vulnerabilities in Windows applications, is
installed on the remote system.");
  # https://support.microsoft.com/en-us/topic/emet-mitigations-guidelines-b529d543-2a81-7b5a-d529-84b30e1ecee0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b2c84d49");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/24");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:enhanced_mitigation_experience_toolkit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_inventory", value:"True");

  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/registry_full_access");
  script_require_ports(139, 445);

  exit(0);
}

include('install_func.inc');
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");


function detect()
{
  var result = {detected:FALSE, audit:AUDIT_NOT_INST};
  var kb_base = "SMB/Microsoft/EMET";
  var versions = {};

  # Uninstall checks
  var uninstall_entry = hotfix_displayname_in_uninstall_key(pattern:display_name);
  if (uninstall_entry)
  {
    dbg::detailed_log(lvl:1, msg:"uninstall entry found: " + uninstall_entry);
    result = {detected:TRUE};

    var version_key = str_replace(string:uninstall_entry, find:'DisplayName', replace:"DisplayVersion");
    var version_string =  get_kb_item(version_key);
    if(!empty_or_null(version_string))
    {
      dbg::detailed_log(lvl:1, msg:"uninstall version found: " + version_string);
      versions['uninstall'] = version_string;
    }
  }

  registry_init();
  var hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

  # Set path 
  path = get_registry_value(handle:hklm, item:"SYSTEM\CurrentControlSet\Services\EMET_Service\ImagePath");

  # Fixup ImagePath by removing characters
  var chars = ['"', 'EMET_Service.exe'];
  foreach var rem (chars)
  {
    path = str_replace(find:rem, replace:"", string:path);
  }
  
  set_kb_item(name:kb_base + "/Path", value:path);

  var file_ver, error, file_path;
  var file = 'EMET_GUI.exe';

  file_path = hotfix_append_path(path:path, value:file);
  file_ver = hotfix_get_fversion(path:file_path);

  error = hotfix_handle_error(
    error_code    : file_ver['error'], 
    file          : file_path, 
    appname       : app, 
    exit_on_fail  : TRUE
  );

  dbg::detailed_log(lvl:1, msg:"file " + file + " version found: " + file_ver['version']);
  versions[file] = file_ver['version'];
  
  # Set detection
  result = {detected:TRUE};

  # Now that we have determined EMET is installed on the host, get a handle to EMET registry AppSettings Subkey
  var emet_reg_handle = RegOpenKey(handle:hklm, key:"SOFTWARE\Microsoft\EMET\AppSettings", mode:MAXIMUM_ALLOWED);
  if (!isnull(emet_reg_handle))
  {
    var emet_query_key = RegQueryInfoKey(handle:emet_reg_handle);
    var emet_reg_name, emet_reg_value;
    var emet_app_list = [];
    ##
    # An EMET registry value for an application where certain exploit mitigation settings
    # are missing may return NULL. This happens when the value for app setting is empty.
    # The data collected from enumerating the EMET AppSettings subkey is meant to be
    # an exact reflection of what is found in the registry, so we will include empty 
    # values where there are no settings for an application.
    #
    # The app and emet setting are separated by a comma to make it easy to access
    # Ex:
    #   EMET Registry Subkey: SOFTWARE\Microsoft\EMET\AppSettings
    #     app                            setting
    #     *\Adobe\*\Reader\AcroRd32.exe, +EAF+ eaf_modules:AcroRd32.dll;Acrofx32.dll;AcroForm.api
    #     *\OFFICE1*\EXCEL.EXE,+ASR asr_modules:flash*.ocx
    #     *\Java\jre*\bin\java.exe, -HeapSpray
    #     *\OFFICE1*\OUTLOOK.EXE,
    ##
    for (var i = 0; !isnull(emet_query_key) && i < emet_query_key[0]; i++)
    {
      emet_reg_name = RegEnumValue(handle:emet_reg_handle, index:i);
      emet_reg_value = RegQueryValue(handle:emet_reg_handle, item:emet_reg_name[1]);
      append_element(value:strcat(emet_reg_name[1], ',', emet_reg_value[1]), var:emet_app_list);
    }

    # Store EMET AppSettings in KB as a list
    set_kb_item(name:kb_base + "/AppSettings", value:serialize(emet_app_list));

    ##
    # Get EMET configuration
    # Ex:
    #   AntiDetours BannedFunctions, DeepHooks, EMET_CE, EnableUnsafeSettings, ExploitAction
    ##
    var emet_config_list = [];
    var emet_config_regs = [
      'AntiDetours', 
      'BannedFunctions', 
      'DeepHooks', 
      'EMET_CE', 
      'EnableUnsafeSettings', 
      'ExploitAction'
    ];
    var value;
    foreach var reg (emet_config_regs)
    {
      value = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\EMET\"+reg);
      if (!isnull(value))
      {
        append_element(value:strcat(reg, ',', value), var:emet_config_list);
      }
    }

    # Store EMET Configuration in KB as a list
    set_kb_item(name:kb_base + "/Config", value:serialize(emet_config_list));
  }
  
  # Close handle and connection
  RegCloseKey(handle:hklm);
  close_registry(close:FALSE);

  # Version priority
  if(result.detected)
  {
    var precedence = ['EMET_GUI.exe', 'uninstall'];
    foreach var ver (precedence)
    {
      if(empty_or_null(versions[ver])) continue;
      version = versions[ver];
      set_kb_item(name:kb_base + "/Version", value:version);
      break;
    }
  }

  return result;
}

##
# Main
##

get_kb_item_or_exit('SMB/registry_full_access');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app   = 'Microsoft Enhanced Mitigation Experience Toolkit';
var cpe   = 'cpe:/a:microsoft:enhanced_mitigation_experience_toolkit';
var extra = {};

var version = UNKNOWN_VER;
var path = '';

var display_name = hotfix_displayname_in_uninstall_key(pattern:'EMET');

if (!display_name) audit(AUDIT_NOT_INST, app);

hotfix_check_fversion_init();

var result = detect();

hotfix_check_fversion_end();

if (!result.detected) audit(result.audit, app);

register_install(
  app_name        : app,
  vendor          : 'Microsoft',
  product         : 'Enhanced Mitigation Experience Toolkit (EMET)',
  path            : path,
  version         : version,
  extra           : extra,
  cpe             : cpe
);

report_installs(app_name:app);

