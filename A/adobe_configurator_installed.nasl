#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62682);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/31");

  script_name(english:"Adobe Configurator Installed");
  script_summary(english:"Checks registry/fs for configurator");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A utility for the Adobe Creative Suite is installed on the remote
host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Adobe Configurator is installed on the remote Windows host.  This is a
utility used to create panels (palettes) that can be used in Photoshop
and InDesign."
  );
  script_set_attribute(attribute:"see_also", value:"https://labs.adobe.com/technologies/configurator/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:adobe:configurator");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("install_func.inc");

app = 'Adobe Configurator';
get_kb_item_or_exit('SMB/Registry/Enumerated');
display_names = get_kb_list_or_exit('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
path_keys = make_list();

foreach key (keys(display_names))
{
  display_name = display_names[key];
  if (display_name !~ '^Adobe Configurator') continue;

  key = key - 'SMB/Registry/HKLM/' - 'DisplayName';
  key = str_replace(string:key, find:'/', replace:"\");
  key += 'DisplayIcon';
  path_keys = make_list(path_keys, key);
  prod_names[key] = display_name;
}

if (max_index(path_keys) == 0)
  audit(AUDIT_NOT_INST, app);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
paths = make_list();

foreach key (path_keys)
{
  ico = get_registry_value(handle:hklm, item:key);
  if (!isnull(ico))
  {
    # the path looks something like C:\program files\configurator\logo.ico
    path_parts = split(ico, sep:"\", keep:TRUE);
    for (i = 0; i < max_index(path_parts) - 1; i++)
      path += path_parts[i];
    paths[path] = prod_names[key];
  }
}

RegCloseKey(handle:hklm);

if (max_index(paths) == 0)
{
  # DisplayName was in the registry without a corresponding InstallLocation
  close_registry();
  exit(1, 'Unable to read install location from the registry.');
}
else
{
  close_registry(close:FALSE);
}

installs = 0;

foreach path (sort(keys(paths)))
{
  # the exe has the version number in it (e.g., Adobe Configurator 3.exe)
  # we figure out what the exe is called by reusing the product name previously
  # found in the registry (e.g., Adobe Configurator 3)
  exe = path + paths[path] + '.exe';

  if (hotfix_file_exists(path:exe))
  {
    set_kb_item(name:'SMB/Adobe_Configurator/Path', value:path);
    set_kb_item(name:'SMB/Adobe_Configurator/ExePath', value:exe);
    register_install(
      vendor:"Adobe",
      product:"Configurator",
      app_name:app,
      path:path,
      extra:make_array('EXE Path', exe),
      cpe:"x-cpe:/a:adobe:configurator");

    installs++;
  }

}

hotfix_check_fversion_end();

if (installs)
{
  port = kb_smb_transport();
  set_kb_item(name:'SMB/Adobe_Configurator/installed', value:TRUE);
  report_installs(app_name:app, port:port);
  exit(0);
}
else audit(AUDIT_UNINST, app);

