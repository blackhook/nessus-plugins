#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(66316);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/06");

  script_xref(name:"IAVT", value:"0001-T-0525");

  script_name(english:"Adobe RoboHelp Installed");
  script_summary(english:"Checks if RH is installed");

  script_set_attribute(attribute:"synopsis", value:"An HTML authoring application is installed on the remote Windows host.");
  script_set_attribute(
    attribute:"description",
    value:
"Adobe RoboHelp, used to author and publish HTML content, is installed
on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.adobe.com/products/robohelp.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:robohelp");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

function detect_robohelp_2020()
{
  # 1. check for uninstall key
  var uninstall_key = hotfix_displayname_in_uninstall_key(pattern:'Adobe RoboHelp 2020');

  if (empty_or_null(uninstall_key))
    audit(AUDIT_NOT_INST, 'Adobe RoboHelp');

  # 2. check Program Files\Adobe\Adobe RoboHelp 2020\RoboHelp.exe
  var dirs = make_list();
  if (!empty_or_null(hotfix_get_programfilesdir()))
    append_element(var:dirs, value:hotfix_get_programfilesdir());
  if (!empty_or_null(hotfix_get_programfilesdirx86()))
    append_element(var:dirs, value:hotfix_get_programfilesdirx86());

  var rh2020_exe = "Adobe\Adobe RoboHelp 2020\RoboHelp.exe" ;
  var dir, file, path, install_count, full_ver, version, port;

  hotfix_check_fversion_init();
  
  foreach dir (dirs)
  {
    file = hotfix_append_path(path:dir, value:rh2020_exe);
    if (hotfix_file_exists(path:file))
    {
      full_ver = hotfix_get_fversion(path:file);
      if (full_ver.error == HCF_OK)
      {
        version = join(full_ver.value, sep:'.');
      }
      
      path = file - 'RoboHelp.exe';

      # versioning seems different for 2020,
      # that's why we register under a different name
      register_install(
          vendor   : 'Adobe',
          product  : 'RoboHelp',
          app_name : 'Adobe RoboHelp 2020', 
          path     : path,
          version  : version,
          cpe      : 'cpe:/a:adobe:robohelp');

      install_count++;
    }
  }

  hotfix_check_fversion_end();
  
  # 3. install, report and exit
  if (install_count > 0)
  {
    port = kb_smb_transport();
    report_installs(app_name:'Adobe RoboHelp 2020', port:port);
    exit(0);
  }
  else
    audit(AUDIT_UNINST, 'Adobe RoboHelp 2020'); 
}

get_kb_item_or_exit('SMB/Registry/Enumerated');

app = 'Adobe RoboHelp';

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

keys = make_list(
  "SOFTWARE\Adobe\RoboHTML",
  "SOFTWARE\Adobe\RoboHelp"
);
paths = make_list(); # key - version, value - path
var key;

foreach key (keys)
{
  subkeys = get_registry_subkeys(handle:hklm, key:key);

  foreach version (subkeys)
  {
    if (version !~ "\d+\.") continue; # ignore keys that don't look like version numbers

    path = get_registry_value(handle:hklm, item:key + "\" + version + "\InstallFolder");
    if (!isnull(path))
      paths[version] = path;
  }
}

RegCloseKey(handle:hklm);

if (max_index(keys(paths)) == 0)
{
  close_registry();
  # we try to detect robohelp 2020
  detect_robohelp_2020();
}
else
{
  close_registry(close:FALSE);
}

installs = 0;
var ver;

foreach ver (keys(paths))
{
  path = paths[ver];
  if (path[strlen(path) - 1] != "\")
    path += "\";

  dll = path + "\redist\roboex32.dll";
  if (hotfix_file_exists(path:dll))
  {
    set_kb_item(name:'SMB/Adobe_RoboHelp/Version', value:ver);
    set_kb_item(name:'SMB/Adobe_RoboHelp/' + ver + '/Path', value:path);

    register_install(
      vendor:"Adobe",
      product:"RoboHelp",
      app_name:app,
      path:path,
      version:ver,
      cpe:"cpe:/a:adobe:robohelp");

    installs++;
  }
}

hotfix_check_fversion_end();

if (installs == 0)
  audit(AUDIT_UNINST, app);

port = kb_smb_transport();
report_installs(app_name:app, port:port);

