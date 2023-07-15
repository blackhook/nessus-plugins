#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67119);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_xref(name:"IAVT", value:"0001-T-0858");

  script_name(english:"McAfee ePolicy Orchestrator Installed (credentialed check)");
  script_summary(english:"Checks registry/fs for epo");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A security management application is installed on the remote Windows
host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"McAfee ePolicy Orchestrator, a centralized security management
application, is installed on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ec37e13");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"asset_categories", value:"security_control");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('install_func.inc');
include('spad_log_func.inc');

var app = 'McAfee ePO';

var display_names = get_kb_list_or_exit('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
var installs = make_array(); # key - uninstall key, value = version (NULL if it couldn't be determined)

# first check the Uninstall keys (stored in the KB) to see if looks like ePO is installed
var key, name, match;
foreach key (keys(display_names))
{
  name = display_names[key];

  # 3.5 - "McAfee ePolicy Orchestrator 3.5.0"
  # 5.0 - "McAfee ePolicy Orchestrator"
  match = pregmatch(string:name, pattern:"^McAfee ePolicy Orchestrator( ([\d.]+))?$");
  if (isnull(match)) continue;

  uninstall_key = key - 'SMB/Registry/HKLM/' - 'DisplayName';
  uninstall_key = str_replace(string:uninstall_key, find:'/', replace:"\");

  # keep track of the version if it's in the display name.
  # the version is used to name the only subdir of the installation directory
  # for older versions of ePO
  installs[uninstall_key] = match[2];
}

if (max_index(keys(installs)) == 0)
  audit(AUDIT_NOT_INST, app);

# If it looks like it's installed, try to get the install path from the registry
registry_init();
var hklm, paths, path, prod_ver;
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
paths = make_list();

foreach key (keys(installs))
{
  path = get_registry_value(handle:hklm, item:key + 'InstallLocation'); # 4.6.5, 5.0
  if (isnull(path))
  {
    path = get_registry_value(handle:hklm, item:key + 'ProductFolder'); # 3.5
    prod_ver = installs[key];
    if (!isnull(path) && !isnull(prod_ver))
      path = path + "\" + prod_ver;
  }

  if (!isnull(path))
    paths = make_list(paths, path);
}

RegCloseKey(handle:hklm);

if (keys(paths) == 0)
{
  close_registry();
  audit(AUDIT_UNINST, app);
}
else
{
  close_registry(close:FALSE);
}

var install_count = 0;

# verify that the installation actually exists. research indicates there will be
# at most one epo installation per host
var exe, status, hotfix_ver, ver, hotfix_path, contents, line, hotfixes, line_list, hotfix, extra;
foreach path (list_uniq(paths))
{
  ver = paths[path];
  if (path[strlen(path) - 1] != "\") # add a trailing slash if necessary
    path += "\";
  exe = path + 'srvmon.exe';
  ver = hotfix_get_fversion(path:exe);
  status = ver['error'];
  if (status != HCF_OK || isnull(ver)) continue;
  ver = join(ver['value'], sep:'.');
  
  #check a few other files for hotfixes. Use the latest version found. 
  hotfix_files = make_list('naimserv.dll', 'dal.dll', 'EventParser.exe');
  hotfix_ver = NULL;
  foreach(file in hotfix_files)
  {  
    exe = path + file;
    hotfix_ver = hotfix_get_fversion(path:exe);
    status = ver['error'];
    hotfix_ver = join(hotfix_ver['value'], sep:'.');
    if (status != HCF_OK || isnull(hotfix_ver)) continue;
    if(ver_compare(fix: hotfix_ver, ver: ver) == -1)
      ver = hotfix_ver;
  }

  # parse installed hotfixes
  hotfixes = make_list();
  extra = make_array();
  hotfix_path = path + "\installed_hotfixes.csv";
  contents = hotfix_get_file_contents(path:hotfix_path);
  spad_log(message:'At first hotfix_get_file_contents() returns: ' + obj_rep(contents));
  hotfix_handle_error(error_code:contents['error'], file:hotfix_path, exit_on_fail:FALSE);
  contents = contents['data'];

  if (!empty_or_null(contents))
  {
    contents = split(contents, sep:'\n', keep:FALSE);
    foreach line (contents)
    {
      line_list = split(line, sep:',', keep:FALSE);
      if (max_index(line_list) > 2)
      {
        hotfix = line_list[1];
        spad_log(message:'Found hotfix: ' + obj_rep(hotfix));
        append_element(var:hotfixes, value:hotfix);
      }
    }
    if (!empty_or_null(hotfixes))
    {
      extra['Hotfixes'] = join(hotfixes, sep:',');
    }
  }

  set_kb_item(name:'SMB/mcafee_epo/Path', value:path);
  set_kb_item(name:'SMB/mcafee_epo/ver', value:ver);

  register_install(
    app_name:app,
    vendor : 'McAfee',
    product : 'ePolicy Orchestrator',
    path:path,
    version:ver,
    cpe:'cpe:/a:mcafee:epolicy_orchestrator',
    extra:extra);

  install_count += 1;
}

hotfix_check_fversion_end();

if (!install_count)
  audit(AUDIT_UNINST, app);

var port = kb_smb_transport();

report_installs(app_name:app, port:port);

