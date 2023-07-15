#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62685);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/31");

  script_name(english:"Adobe Drive Installed");
  script_summary(english:"Checks registry & file system for Drive");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A digital asset management application is installed on the remote
host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Adobe Drive is installed on the remote Windows host.  Drive provides
digital asset management that integrates with other applications in the
Adobe Creative Suite."
  );
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/drive/faq.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:adobe:drive");
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

app = 'Adobe Drive';
get_kb_item_or_exit('SMB/Registry/Enumerated');
display_names = get_kb_list_or_exit('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
path_keys = make_list();

foreach key (keys(display_names))
{
  display_name = display_names[key];
  if (display_name !~ '^Adobe Drive (CS)?[0-9.]+$') continue;

  key = key - 'SMB/Registry/HKLM/' - 'DisplayName';
  key = str_replace(string:key, find:'/', replace:"\");
  key += 'InstallLocation';
  path_keys = make_list(path_keys, key);
}

if (max_index(path_keys) == 0)
  audit(AUDIT_NOT_INST, app);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
paths = make_list();

foreach key (path_keys)
{
  path = get_registry_value(handle:hklm, item:key);
  if (!isnull(path))
    paths = make_list(paths, path);
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
foreach path (paths)
{
  exe = path + "\ConnectUI\Adobe Drive.exe";
  version = NULL;

  ver =  hotfix_get_fversion(path:exe);
  if (ver['error'] == HCF_OK)
    version = join(ver['value'], sep:'.');
  else
    continue;

  set_kb_item(name:'SMB/Adobe_Drive/'+version+'/Path', value:path);

  register_install(
    vendor:"Adobe",
    product:"Drive",
    app_name:app,
    path:path,
    version:version,
    cpe:"x-cpe:/a:adobe:drive");

  installs++;
}

hotfix_check_fversion_end();

if (installs)
{
  port = kb_smb_transport();
  set_kb_item(name:'SMB/Adobe_Drive/installed', value:TRUE);
  report_installs(app_name:app, port:port);
  exit(0);
}
else audit(AUDIT_UNINST, app);
