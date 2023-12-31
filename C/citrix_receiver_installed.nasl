#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62309);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_name(english:"Citrix Receiver Installed");
  script_summary(english:"Checks for Citrix Receiver");

  script_set_attribute(attribute:"synopsis", value:"A remote access application is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"Citrix Receiver, a client application for accessing documents from
multiple locations, is installed on the remote Windows host.");
  # https://www.citrix.com/products/?contentID=1689163
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?677e5b2f");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:receiver");
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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'Citrix Receiver';
port = kb_smb_transport();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Citrix\Install\ReceiverInsideForOnline\InstallFolder";
path = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}
else close_registry(close:FALSE);

exe = path + "\Receiver.exe";
ver = hotfix_get_fversion(path:exe);
hotfix_check_fversion_end();

if (ver['error'] == HCF_NOENT)
  audit(AUDIT_UNINST, app);
else if (ver['error'] != HCF_OK)
  exit(1, "Failed to obtain the file version of '" + exe + "'.");

version = join(sep:'.', ver['value']);
set_kb_item(name:'SMB/'+app+'/Path', value:path);
set_kb_item(name:'SMB/'+app+'/Version', value:version);
register_install(
  app_name:app,
  vendor : 'Citrix',
  product : 'Receiver',
  path:path,
  version:version,
  cpe:"cpe:/a:citrix:receiver");

report_installs(app_name:app, port:port);

