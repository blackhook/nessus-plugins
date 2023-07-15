#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66764);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_name(english:"Nitro Reader Installed");
  script_summary(english:"Checks for Nitro Reader");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has a PDF reader installed.");
  script_set_attribute(attribute:"description", value:"Nitro Reader, a PDF reader, is installed on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"https://www.gonitro.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nitropdf:nitro_pdf");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
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

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'Nitro Reader';
port = kb_smb_transport();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
paths = make_list();
key = "SOFTWARE\Nitro\Reader";
subkeys = get_registry_subkeys(handle:hklm, key:key);
if (!isnull(subkeys))
{
  foreach subkey (subkeys)
  {
    if (subkey =~ '^[0-9\\.]+$')
    {
      path = get_registry_value(handle:hklm, item:key + '\\' + subkey + "\NitroPDFCreator\App Dir");
      if (!isnull(path)) paths = make_list(paths, path);
    }
  }
}
 # Older versions
key = "SOFTWARE\Nitro PDF\Reader";
subkeys = get_registry_subkeys(handle:hklm, key:key);
if (!isnull(subkeys))
{
  foreach subkey (subkeys)
  {
    if (subkey =~ '^[0-9\\.]+$')
    {
      path = get_registry_value(handle:hklm, item:key + '\\' + subkey + "\NitroPDFCreator\App Dir");
      if (!isnull(path)) paths = make_list(paths, path);
    }
  }
}
RegCloseKey(handle:hklm);

if (max_index(paths) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}
close_registry(close:FALSE);

installs = 0;

foreach path (list_uniq(paths))
{
  exe = path + 'NitroPDFReader.exe';

  ver = hotfix_get_fversion(path:exe);
  if (ver['error'] != HCF_OK) continue;

  version = join(ver['value'], sep:'.');

  path_parts = split(exe, sep:'\\', keep:TRUE);
  path = '';
  for (i = 0; i < max_index(path_parts) - 1; i++)
    path += path_parts[i];

  installs++;
  set_kb_item(name:'SMB/Nitro Reader/' + version + '/Path', value:path);

  register_install(
    app_name:app,
    vendor : 'Nitropdf',
    product : 'Nitro PDF',
    path:path,
    version:version,
    cpe:"cpe:/a:nitropdf:nitro_pdf");
}
hotfix_check_fversion_end();

if (installs)
{
  set_kb_item(name:'SMB/Nitro Reader/installed', value:TRUE);
  report_installs(app_name:app, port:port);
  exit(0);
}
else audit(AUDIT_UNINST, app);
