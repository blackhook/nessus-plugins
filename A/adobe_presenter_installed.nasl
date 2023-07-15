#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62691);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/31");

  script_name(english:"Adobe Presenter Installed");
  script_summary(english:"Checks for Presenter in the registry/fs");

  script_set_attribute(attribute:"synopsis", value:"A video editing application is installed on the remote host.");
  script_set_attribute(
    attribute:"description",
    value:
"Adobe Presenter, a video production / editing application, is installed
on the remote Windows host."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.adobe.com/products/presenter.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:adobe_presenter");
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

app = 'Adobe Presenter';

get_kb_item_or_exit('SMB/Registry/Enumerated');

paths = make_list();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Adobe\Adobe Presenter";
subkeys = get_registry_subkeys(handle:hklm, key:key);

foreach subkey (subkeys)
{
  if (subkey !~ '^[0-9.]+$') continue;

  path = get_registry_value(handle:hklm, item:key + "\" + subkey + "\Path");
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

installs = 0;

foreach path (paths)
{
  dll = path + 'ProducerUI.dll';
  version = NULL;
  verui = NULL;

  ver =  hotfix_get_fversion(path:dll);
  if (ver['error'] == HCF_NOVER)
    version = 'Unknown';
  else if (ver['error'] == HCF_OK)
    version = join(ver['value'], sep:'.');
  else
    continue;

  set_kb_item(name:'SMB/Adobe_Presenter/'+version+'/Path', value:path);

  register_install(
    vendor:"Adobe",
    product:"Adobe Presenter",
    app_name:app,
    path:path,
    version:version,
    cpe:"cpe:/a:adobe:adobe_presenter");

  installs++;
}

hotfix_check_fversion_end();

if (installs)
{
  port = kb_smb_transport();
  set_kb_item(name:'SMB/Adobe_Presenter/installed', value:TRUE);
  report_installs(app_name:app, port:port);
  exit(0);
}
else audit(AUDIT_UNINST, app);
