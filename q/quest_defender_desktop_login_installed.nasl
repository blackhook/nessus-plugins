#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65929);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/06");

  script_name(english:"Quest Defender Desktop Login Component Installed");
  script_summary(english:"Checks for Quest Defender Desktop Login Component");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a two-factor authentication application
installed.");
  script_set_attribute(attribute:"description", value:
"Defender Desktop Login Component, a two-factor authentication
application for protecting a login page, is installed on the remote
Windows host.");
  script_set_attribute(attribute:"see_also", value:"https://www.oneidentity.com/products/defender/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/11");

  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:quest:defender");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'Quest Defender Desktop Login Component';
port = kb_smb_transport();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = 'SOFTWARE\\PassGo Technologies\\Defender\\Defender GINA\\';
path = get_registry_value(handle:hklm, item:key);

RegCloseKey(handle:hklm);
if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}
close_registry(close:FALSE);

exe = path + "\GetTokens.exe";
ver = hotfix_get_fversion(path:exe);
hotfix_check_fversion_end();

if (ver['error'] == HCF_NOENT) audit(AUDIT_UNINST, app);
else if (ver['error'] != HCF_OK) audit(AUDIT_VER_FAIL, exe);

version = join(ver['value'], sep:'.');
kb_base = 'SMB/' + app + '/';
set_kb_item(name:kb_base + 'Path', value:path);
set_kb_item(name:kb_base + 'Version', value:version);

register_install(
  vendor:"Quest",
  product:"Defender",
  app_name:app,
  path:path,
  version:version,
  cpe:"x-cpe:/a:quest:defender");

report_installs(app_name:app, port:port);

