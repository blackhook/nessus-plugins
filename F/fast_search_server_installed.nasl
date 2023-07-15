#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60154);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/31");

  script_name(english:"Microsoft FAST Search Server Installed");
  script_summary(english:"Checks if the software is installed");

  script_set_attribute(attribute:"synopsis", value:"A search application is installed on the remote Windows host.");
  script_set_attribute(
    attribute:"description",
    value:
"Microsoft FAST Search Server, an enterprise search application, is
installed on the remote host."
  );
  # https://products.office.com/en-us/sharepoint/collaboration?ms.officeurl=sharepoint&rtc=1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dcce8700");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:fast_search_server");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_ports(139, 445);
  script_require_keys("SMB/Registry/Enumerated");

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

app = 'FAST Search Server';

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Microsoft\FAST Search Server\Setup";
names = make_list('Path', 'ProductType');
values = get_values_from_key(handle:hklm, entries:names, key:key);
path = values['Path'];
prodtype = values['ProductType'];
RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}
else
  close_registry(close:FALSE);

exists = hotfix_file_exists(path:path + "\bin\fastsearch.exe");
hotfix_check_fversion_end();

if (!exists)
  audit(AUDIT_UNINST, app);

set_kb_item(name:'SMB/fast_search_server/path', value:path);

extra = make_array();
if (!isnull(prodtype))
{
  set_kb_item(name:'SMB/fast_search_server/prodtype', value:prodtype);
  extra['Product Type'] = prodtype;
}

register_install(
  vendor:"Microsoft",
  product:"FAST Search Server",
  app_name:app,
  path:path,
  extra:extra,
  cpe:"x-cpe:/a:microsoft:fast_search_server");

report_installs(app_name:app, port:kb_smb_transport());

