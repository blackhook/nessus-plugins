#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58847);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_name(english:"Intuit QuickBooks Installed");
  script_summary(english:"Checks registry/file system for QB");

  script_set_attribute(attribute:"synopsis", value:"Business accounting software is installed on the remote Windows host.");
  script_set_attribute(
    attribute:"description",
    value:
"QuickBooks, accounting software for small businesses, is installed on
the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"https://quickbooks.intuit.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:intuit:quickbooks");
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

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

port = kb_smb_transport();
appname = 'QuickBooks';

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Intuit\QuickBooks";
qb_subkeys = get_registry_subkeys(handle:hklm, key:key);
products = make_array();

foreach ver (qb_subkeys)
{
  if (ver !~ "^[0-9.]+$") continue;

  # different editions of QB have install information in different subkeys. e.g., for Enterprise Solutions it's "bel"
  ver_key = key + "\" + ver;
  ver_subkeys = get_registry_subkeys(handle:hklm, key:ver_key);

  foreach edition (ver_subkeys)
  {
    edition_key = ver_key + "\" + edition;
    values = get_values_from_key(handle:hklm, key:edition_key, entries:make_list('Path', 'Product'));
    path = values['Path'];
    prod = values['Product'];

    if (isnull(path)) continue;
    if (isnull(prod)) prod = 'n/a';
    products[path] = prod;
  }
}

RegCloseKey(handle:hklm);

if (max_index(keys(products)) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
else
  close_registry(close:FALSE);

install_count = 0;

foreach path (keys(products))  # 'path' should be the absolute path to an exe
{
  if (!hotfix_file_exists(path:path)) continue;

  # extract the dir from the path
  parts = split(path, sep:"\", keep:FALSE);
  dir = '';
  for (i = 0; i < max_index(parts) - 1; i++)
    dir += parts[i] + "\";

  prod = products[path];
  install_count += 1;
  set_kb_item(name:'SMB/QuickBooks/' + prod + '/path', value:dir);

  register_install(
    app_name:appname,
    vendor : 'Intuit',
    product : 'Quickbooks',
    path:dir,
    cpe:"cpe:/a:intuit:quickbooks");
}

hotfix_check_fversion_end();

if (!install_count)
  audit(AUDIT_UNINST, appname);
else
  set_kb_item(name:'SMB/QuickBooks/Installed', value:TRUE);

report_installs(app_name:appname, port:port);

