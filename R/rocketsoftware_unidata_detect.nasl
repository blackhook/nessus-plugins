#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(51461);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/06");

  script_name(english:"Rocket Software UniData Detection");
  script_summary(english:"Checks for Rocket Software UniData");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host is running a relational database.");

  script_set_attribute(attribute:"description", value:
"The remote Windows host is running UniData, a relational database
application.");

  script_set_attribute(attribute:"see_also", value:"https://www.rocketsoftware.com/products/rocket-unidata-0/rocket-unidata");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:rocketsoftware:unidata");
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

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');
include("install_func.inc");

app = 'Rocket Software UniData';

get_kb_item_or_exit('SMB/Registry/Enumerated');

# Connect to the appropriate share.
name    = kb_smb_name();
port    = kb_smb_transport();
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();

registry_init();
hive = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = 'SOFTWARE\\IBM\\UniData';
subkeys = get_registry_subkeys(handle:hive, key:key);

# Get the install path
paths = make_list();
foreach subkey (subkeys)
{
  if (subkey =~ '^[0-9\\.]+$')
  {
    entry = key + '\\' + subkey + '\\UDTHOME';
    path = get_registry_value(handle:hive, item:entry);
    if (!isnull(path)) paths = make_list(paths, path);
  }
}

# Newer versions of the software create a different registry key
key = 'SOFTWARE\\Rocket Software\\UniData';
subkeys = get_registry_subkeys(handle:hive, key:key);
foreach subkey (subkeys)
{
  if (subkey =~ '^[0-9\\.]+$')
  {
    entry = key + '\\' + subkey + '\\UDTHOME';
    path = get_registry_value(handle:hive, item:entry);
    if (!isnull(path)) paths = make_list(paths, path);
  }
}
RegCloseKey(handle:hive);

if (max_index(paths) < 1)
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}
close_registry(close:FALSE);

install_count = 0;
foreach path (paths)
{
  dll = path + "\bin\unidata.dll";
  ver = hotfix_get_fversion(path:dll);

  if (isnull(ver['value']))
  {
    version = 'Unknown';
    debug_print('Couldn\'t get the version of '+path+"\bin\unidata.dll");
  }
  else
  {
    verarr = ver['value'];
    version = verarr[0] + '.' + verarr[1] + '.' + verarr[2];
    build = verarr[3];
  }
  version += '.' + build;

  set_kb_item(name:'SMB/RocketSoftware/UniData/'+version+'/path', value:path);

  register_install(
    vendor:"Rocket Software",
    product:"UniData",
    app_name:app,
    path:path,
    version:version,
    extra:make_array('Build', build),
    cpe:"x-cpe:/a:rocketsoftware:unidata"
  );

  install_count += 1;
}
hotfix_check_fversion_end();

if (install_count)
{
  set_kb_item(name:'SMB/RocketSoftware/UniData/installed', value:TRUE);
  report_installs(app_name:app, port:port);
  exit(0);
}
else exit(0, 'No Rocket Software UniData installs were detected on the remote host.');
