#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62681);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_name(english:"Adobe Bridge Installed");
  script_summary(english:"Checks for Bridge.exe.");

  script_set_attribute(attribute:"synopsis", value:
"A digital management application is installed on the remote Windows
host.");
  script_set_attribute(attribute:"description", value:
"Adobe Bridge is installed on the remote Windows host. Bridge is used
to organize creative assets, and provide centralized access for
applications in the Adobe Creative Suite.");
  script_set_attribute(attribute:"see_also", value:"https://www.adobe.com/products/bridge.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:bridge");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:bridge_cc");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

app = 'Adobe Bridge';
get_kb_item_or_exit('SMB/Registry/Enumerated');

paths = make_list();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Adobe\Adobe Bridge";
subkeys = get_registry_subkeys(handle:hklm, key:key);

foreach subkey (subkeys)
{
  # Product "CC 2020" goes by just "2020"
  if (subkey !~ "^CS[0-9]+$" && subkey !~ "^CC(\s[0-9]{4})?$" && subkey !~ "^20[0-9]{2}$") continue;

  path = get_registry_value(handle:hklm, item:key + "\" + subkey + "\Installer\InstallPath");
  if (!isnull(path))
    paths = make_list(paths, path);
}

RegCloseKey(handle:hklm);

if (max_index(paths) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}
else
{
  close_registry(close:FALSE);
}

install_count = 0;

foreach path (paths)
{
  exe = path + "\Bridge.exe";
  version = NULL;
  verui = NULL;

  ver =  hotfix_get_fversion(path:exe);
  if (ver['error'] == HCF_NOVER)
    version = 'Unknown';
  else if (ver['error'] == HCF_OK)
  {
    ver = ver['value'];
    version = join(ver, sep:'.');
  }
  else continue;

  product = hotfix_get_pname(path:exe);
  if ( product['error'] == HCF_OK)
  {
    product = product['value'];
  }
  else continue;

  set_kb_item(name:'SMB/Adobe_Bridge/'+version+'/Path', value:path);
  set_kb_item(name:'SMB/Adobe_Bridge/'+version+'/Version', value:version);
  set_kb_item(name:'SMB/Adobe_Bridge/'+version+'/Product', value:product);

  register_install(
    app_name:app,
    vendor : 'Adobe',
    product : 'Bridge CC',
    path:path,
    version:version,
    extra: make_array('Product', product),
    cpe:"cpe:/a:adobe:bridge");

  install_count += 1;
}

hotfix_check_fversion_end();

if (install_count)
{
  port = kb_smb_transport();
  set_kb_item(name:'SMB/Adobe_Bridge/installed', value:TRUE);
  report_installs(app_name:app, port:port);
  exit(0);
}
else audit(AUDIT_UNINST, app);

