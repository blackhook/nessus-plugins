#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93962);
  script_version("1.180");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/26");

  script_name(english:"Microsoft Security Rollup Enumeration");
  script_summary(english:"Enumerates installed Microsoft security rollups.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin enumerates installed Microsoft security rollups.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to enumerate the Microsoft security rollups installed
on the remote Windows host.");
  # https://blogs.technet.microsoft.com/windowsitpro/2016/08/15/further-simplifying-servicing-model-for-windows-7-and-windows-8-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b23205aa");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/11");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "wmi_enum_qfes.nbin", "smb_enum_qfes.nasl", "dism_enum_packages.nbin", "wevtutil_removed_packages.nbin");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_timeout(30*60);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("debug.inc");
include("smb_rollup_data.inc");

# rollup_dates has now been moved to smb_rollup_data.inc so it can be handled by automation

##
# gets a file version and saves it in the KB
#
# @param path absolute pathname of file to get version for
#
# @return an array where
#         'error' = augmented comparison error code
#         'version' = file version, if one could be obtained
# .       'report' = report text for downstream plugins
##
function rollup_fcheck(path, fix)
{
  local_var fver, r_code, cmp_result, report;
  
  fver = hotfix_get_fversion(path:path);

  if (isnull(fver) || empty_or_null(fver['error']))
    return {error:HCF_ERR, version:''}; # Function failed; This shouldn't happen

  if (fver['error'] == HCF_OK)
  {
    cmp_result = ver_compare(ver:fver['version'], fix:fix, strict:FALSE);

    if (isnull(cmp_result))
      return {error:HCF_ERR, version:fver['version']};
    else if (cmp_result >= 0)
      return {error:HCF_OK, version:fver['version']};
    else
    {
      report = '  - ' + path + ' has not been patched.\n'
             + '    Remote version : ' + fver['version'] + '\n'
             + '    Should be      : ' + fix + '\n';
      return {error:HCF_OLDER, version:fver['version'], report:report};
    }
  }
  else
  {
    report = '  - An error occured while attempting to check ' + path + '\n'
           +     'Error Code       : ' + fver['error'] + '\n';
    return {error:fver['error'], report:report};
  }
}

function set_rollup_info(rollup, path, fver_arr)
{
  local_var error, version, report;
  if (isnull(rollup) || isnull(fver_arr) || isnull(path))
    return FALSE;
    
  if (!isnull(fver_arr['error']))
  {
    error = fver_arr['error'];
    replace_kb_item(name:'smb_rollup/' + rollup + '/error_code', value:fver_arr['error']);
    replace_kb_item(name:'smb_rollup/' + rollup + '/file', value:path);
    if (!isnull(fver_arr['version'])) replace_kb_item(name:'smb_rollup/' + rollup + '/file_ver', value:fver_arr['version']);
  
    if (!isnull(fver_arr['report']))
    {
      report = get_kb_item('smb_rollup/version_report/' + rollup);
      if (!empty_or_null(report))
        report += fver_arr['report'];
      else
        report = fver_arr['report'];
  
      replace_kb_item(name:'smb_rollup/version_report/' + rollup, value:report); 
    }
    return TRUE;
  }
  else
  {
    return FALSE;
  }
}

function is_patched(file_check, rollup_date)
{
  local_var my_sp, my_os, my_arch, my_os_build, systemroot;
  local_var path, error_code, fver_arr;
  
  my_os = get_kb_item("SMB/WindowsVersion");
  my_sp = get_kb_item("SMB/CSDVersion");
  my_arch = get_kb_item("SMB/ARCH");
  my_os_build = get_kb_item("SMB/WindowsVersionBuild");
  if ( my_sp )
  {
    my_sp = ereg_replace(pattern:".*Service Pack ([0-9]).*", string:my_sp, replace:"\1");
    my_sp = int(my_sp);
  }
  else my_sp = 0;

  if ( file_check['os'] >!< my_os ) return FALSE;
  if ( !empty_or_null(file_check['sp']) && my_sp != file_check['sp'] ) return FALSE;
  if ( !empty_or_null(file_check['arch']) && my_arch != file_check['arch'] ) return FALSE;
  if ( !empty_or_null(file_check['os_build']) && my_os_build != file_check['os_build'] ) return FALSE;
  if (isnull(file_check['path']) || isnull(file_check['file'])) return FALSE;

  systemroot = hotfix_get_systemroot();
  if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

  
  
  path = hotfix_append_path(path:systemroot + file_check['path'], value:file_check['file']);

  # Look and see if we already have a confirmed patched file for this specific
  #  rollup. This can happen when multiple files are allowed (hotpatch)
  error_code = get_kb_item('smb_rollup/' + rollup_date + '/error_code');
  if (!empty_or_null(error_code) && error_code == HCF_OK)
    return FALSE;

  # Run rollup-specific fcheck
  fver_arr = rollup_fcheck(path:path, fix:file_check['version']);
  if (isnull(fver_arr) || isnull(fver_arr['error']))
  {
    dbg::log(src:'is_patched()', msg:'rollup_fcheck() function error');
    return FALSE;
  }

  if (!set_rollup_info(rollup:rollup_date, path:path, fver_arr:fver_arr))
    dbg::log(src:'is_patched()', msg:'set_rollup_info() function error');

  if (fver_arr['error'] == HCF_OK)
  {
    replace_kb_item(name:'smb_rollup/fa_info/' + rollup_date, value:'1;' + path + ';' + file_check['version'] + ';' + fver_arr['version']);
    return TRUE;
  }
  else
  {
    replace_kb_item(name:'smb_rollup/fa_info/' + rollup_date, value:'0;' + path + ';' + file_check['version'] + ';' + fver_arr['version']);
    return FALSE;
  }
}

function is_patched_hp(file_check, rollup_date, hp_table)
{
  local_var is_patched, f_tab, entry;

  f_tab = hp_table[file_check['file']];

  if (!isnull(f_tab))
  { 
    foreach entry (f_tab)
    {
      if (isnull(file_check['com_hint']) || file_check['com_hint'] >< entry['path'])
      {
        file_check['path'] = entry['path']; # This is safe. A function operates on a copy unless a reference is specifically used.
        return is_patched(file_check:file_check, rollup_date:rollup_date);
      }
    }
  }
  return FALSE;
}

function gen_hp_table(hp_table)
{
  var key, hklm, r_table, r_key;
  var value, subkey, subkeys;
  var path, file, match;

  if (isnull(hp_table)) hp_table = {};

  key = 'SYSTEM\\CurrentControlSet\\Control\\HotPatch';

  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE);
  if (isnull(hklm))
  {
    close_registry();
    dbg::detailed_log(lvl:1, src:'gen_hp_table', msg:'Failed to connect to HKLM for HP table.'); 
    audit(AUDIT_REG_FAIL);
  }

  # Old Style
  r_table = get_reg_name_value_table(handle:hklm, key:key);
  dbg::detailed_log(lvl:3, src:'gen_hp_table', msg:'OS: r_table collection\n' + obj_rep(r_table));

  if (!isnull(r_table))
  {
    foreach r_key (keys(r_table))
    {
      r_table[r_key] = unicode2ascii(string:r_table[r_key]);
    }
  }

  # New Style
  subkeys = get_registry_subkeys(handle:hklm, key:key);
  dbg::detailed_log(lvl:3, src:'gen_hp_table', msg:'NS: subkey collection\n' + obj_rep(subkeys)); 
  if (!isnull(subkeys))
  {
    foreach subkey (subkeys)
    {
      value = get_registry_value(handle:hklm, item:join(key, subkey, 'PatchPath', sep:'\\'));
      if (!isnull(value))
      {
        r_table[subkey] = value;
        dbg::detailed_log(lvl:3, src:'gen_hp_table', msg:'NS: r_table addition\nkey: '+ obj_rep(subkey) + '\nvalue: ' + obj_rep(value));
      }
    }
  }
  RegCloseKey(handle:hklm);
  close_registry(close:FALSE);

  dbg::detailed_log(lvl:3, src:'gen_hp_table', msg:'Final r_table collection\n' + obj_rep(r_table));
  if (!isnull(r_table))
  {
    foreach key (keys(r_table))
    {
      # \Systemroot\WinSxs\wow64_microsoft-windows-t..e-package-component_31bf3856ad364e35_10.0.17784.10000_none_55e77d3f6de6933f\rpcrt4_hp.dll
      # 
      match = pregmatch(pattern:"^.+?Systemroot(\\.+)\\([^\\]+)$", string:r_table[key]);
      if (!isnull(match))
      {
        file = match[2];
        path = match[1];

        if (isnull(hp_table[file]))
          hp_table[file] = [];

        append_element(var:hp_table[file], value:{path:path, key:key});
        dbg::detailed_log(lvl:3,  src:'gen_hp_table', msg:'Added table value:', msg_details:{'File':{lvl:3, value:file}, 'Path':{lvl:3, value:path}, 'Key':{lvl:3, value:key}});
      }
      else
        dbg::detailed_log(lvl:1, src:'gen_hp_table', msg:'Failed to parse table value: ' + obj_rep(r_table(key))); 
    }
  }
  dbg::detailed_log(lvl:1, src:'gen_hp_table', msg:'Generated hp_table array', msg_details:{'Table':{lvl:2, value:obj_rep(hp_table)}});
  
  return hp_table;
  # e.g. (64 and 32-bit dlls):
  # make_nested_array(
  #   'rpcrt4_hp.dll', make_nested_list(
  #     make_nested_array(
  #       'key', '00130a96469abda4',
  #       'path', '\\WinSxs\\amd64_microsoft-windows-t..e-package-component_31bf3856ad364e35_10.0.17784.10000_none_4b92d2ed3985d144'
  #     ),
  #     make_nested_array(
  #       'key', '000cb198782e75d3',
  #       'path', '\\WinSxs\\wow64_microsoft-windows-t..e-package-component_31bf3856ad364e35_10.0.17784.10000_none_55e77d3f6de6933f'
  #     )
  #   )
  # )
}

function rollupfix_installed()
{
  var file_ver, dism_rollupfix;
  if(!isnull(_FCT_ANON_ARGS[0])) file_ver = _FCT_ANON_ARGS[0];

  dism_rollupfix = get_kb_item("WMI/DISM/rollupfix");
  if(!isnull(dism_rollupfix) && !isnull(os_ver))
  {
    if(os_ver == "10")
      dism_rollupfix = os_ver + ".0." + dism_rollupfix;
    else
      dism_rollupfix = os_ver + "." + dism_rollupfix;
  }

  if(!isnull(dism_rollupfix) && ver_compare(ver:dism_rollupfix, fix:file_ver, strict:FALSE) >= 0)
    return TRUE;
}

function kb_installed()
{
  var kb, qfes, wevt_removed, dism;
  if(isnull(_FCT_ANON_ARGS[0])) return false;
  kb = "KB" + _FCT_ANON_ARGS[0];
  qfes = get_kb_item("SMB/Microsoft/qfes");
  dism = get_kb_item("WMI/DISM/installed");
  wevt_removed = get_kb_item("WMI/WEVTUTIL/removed");
  if((kb >< qfes) || get_kb_item("WMI/Installed/Hotfix/" + kb) || (kb >< dism) || (kb >< wevt_removed))
    return TRUE;
}

function check_handler(file_check, rollup_date, hp_table)
{
  if (empty_or_null(file_check)) 
  {
    dbg::log(src:'check_handler()', msg:'Provided an empty or null file_check.'); 
    return 0;
  }

  if (file_check['type'] == 'hp')
  {
    if (!get_kb_item("SMB/WindowsHPEnrollment"))
      return 0;

    if (empty_or_null(hp_table)) 
    {
      dbg::log(src:'check_handler()', msg:'hp_table not provided with hp check.');
      return 0;
    }

    return is_patched_hp(file_check:file_check,
                         hp_table:hp_table,
                         rollup_date:rollup_date);
  }
  else
  {
    return is_patched(file_check:file_check, rollup_date:rollup_date); 
  }
}

var report = '';
var latest_eff = '';
var cur_date = '0.0';
var last_date = '0.0';
var latest_file = '';
var latest_ver = '';
var kb_str = '';
var oob_installed = '';
var systemroot = hotfix_get_systemroot();
var smb_qfes = get_kb_item('SMB/Microsoft/qfes');
var wmi_qfes = get_kb_list('WMI/Installed/Hotfix/*');
global_var os_ver = get_kb_item("SMB/WindowsVersion");
var hp_table = {};

if (get_kb_item("SMB/WindowsHPEnrollment"))
{
  report += '\n Hotpatching       : Enrolled';
  hp_table = gen_hp_table();
}

foreach var rollup_date (rollup_dates)
{
  var patch_checks = rollup_patches[rollup_date];
  foreach var patch_check (patch_checks)
  {
    var file_check = patch_check[0];
    if(check_handler(file_check:file_check, rollup_date:rollup_date, hp_table:hp_table))
    {
      
      var kb_list = patch_check[1];

      # 09_2020, 09_2020_2, 09_2020_02_1, etc
      if (rollup_date !~ "^[0-9]+_[0-9][0-9_]*$")
      {
        dbg::log(src:'rollup date loop', msg:'Rollup string failed regex check - rollup_date: ' + obj_rep(rollup_date));
        continue;
      }

      var key_segs = split(rollup_date, sep:'_', keep:FALSE);
      var int_var = key_segs[0];
      key_segs[0] = key_segs[1];
      key_segs[1] = int_var;
      cur_date = join(key_segs, sep:'.');

      if(kb_installed(kb_list["cum"]) || kb_installed(kb_list["pre"]) || max_index(kb_list["oob"]) > 0 || os_ver == "10" || rollupfix_installed(file_check["version"]))
      {
        if (empty_or_null(latest_eff)) latest_eff = rollup_date;

        # 09_2020, 09_2020_2, 09_2020_02_1, etc
        if (latest_eff !~ "^[0-9]+_[0-9][0-9_]*$")
        {
          dbg::log(src:'rollup date loop', msg:'Rollup string failed regex check - latest_eff: ' + obj_rep(latest_eff));
          continue;
        }
        key_segs = split(latest_eff, sep:'_', keep:FALSE);
        int_var = key_segs[0];
        key_segs[0] = key_segs[1];
        key_segs[1] = int_var;
        last_date = join(key_segs, sep:'.');

        if(ver_compare(ver:cur_date, fix:last_date, strict:FALSE) >=0)
        {
          latest_eff = rollup_date;

          kb_str =  kb_list["cum"];
          if(kb_list['oob']) kb_str += ", " + join(kb_list['oob'], sep:", ");
          if(kb_list['sec']) kb_str += ", " + kb_list['sec'];
          if(kb_list['pre']) kb_str += ", " + kb_list['pre'];
        }
      }

      if(os_ver == "10")
      {
        if(kb_installed(kb_list["cum"]))
        {
          report += '\n Cumulative Rollup : ' + rollup_date + ' [KB' + kb_list["cum"] + ']';
          set_kb_item(name:"smb_rollup/" + rollup_date + "/cum", value:kb_list["cum"]);
        }
        if(oob_installed) // todo: research-how-used
        {
          foreach var patch (kb_list["oob"])
          {
            if(kb_installed(patch))
            {
              report += '\n Cumulative Rollup : ' + rollup_date + ' [KB' + patch + ']';
              set_kb_item(name:"smb_rollup/" + rollup_date + "/oob", value:patch);
            }
          }
        }
        if(!kb_installed(kb_list["cum"]) && !oob_installed)
        {
          report += '\n Cumulative Rollup : ' + rollup_date;
          set_kb_item(name:"smb_rollup/" + rollup_date, value:1);
        }
      }
      else
      {
         if(kb_installed(kb_list["cum"]))
        {
          report += '\n Cumulative Rollup : ' + rollup_date + ' [KB' + kb_list["cum"] + ']';
          set_kb_item(name:"smb_rollup/" + rollup_date + "/cum", value:kb_list["cum"]);
        }

        if(kb_installed(kb_list["pre"]))
        {
          report += '\n Preview of Monthly Rollup : ' + rollup_date + ' [KB' + kb_list["pre"] + ']';
          set_kb_item(name:"smb_rollup/" + rollup_date + "/preview", value:kb_list["pre"]);
        }
        if(kb_installed(kb_list["sec"]))
        {
          report += '\n Security Rollup : ' + rollup_date + ' [KB' + kb_list["sec"] + ']';
          set_kb_item(name:"smb_rollup/" + rollup_date + "/sec", value:kb_list["sec"]);
          set_kb_item(name:"smb_rollup/"+rollup_date, value:1);
        }

        # If no qfes could be enumerated, but versions are right
        # defer to the version check.
        if(empty_or_null(smb_qfes) && empty_or_null(wmi_qfes))
        {
          set_kb_item(name:"smb_rollup/"+rollup_date, value:1);
        }
      }
    }
  }
}

# cleanup connection
NetUseDel();

replace_kb_item(name:"smb_check_rollup/done", value:TRUE);

foreach var error_code (make_list(get_kb_list("smb_rollup/*/error_code")))
{
  if (!isnull(error_code) && error_code != HCF_OK
                          && error_code != HCF_OLDER 
                          && error_code != HCF_NOENT)
    {
      replace_kb_item(name:"smb_check_rollup/done", value:FALSE);
      break;
    }
}

if(latest_eff == "" && report == "")
  exit(0, "No Microsoft rollups were found.");

latest_file = get_kb_item("smb_rollup/"+latest_eff+"/file");
latest_ver = get_kb_item("smb_rollup/"+latest_eff+"/file_ver");

if(latest_eff == "")
{
  set_kb_item(name:"smb_rollup/latest", value:"none");
  report += '\n   No cumulative updates are installed.\n';
}
else
{    
  report += '\n\n Latest effective update level : ' + latest_eff +
            '\n File checked                  : ' + latest_file +
            '\n File version                  : ' + latest_ver +
            '\n Associated KB                 : ' + kb_str + '\n';
  set_kb_item(name:"smb_rollup/latest", value:latest_eff);
}

var port = kb_smb_transport();
if(!port)port = 445;

security_note(port:port, extra:report);
