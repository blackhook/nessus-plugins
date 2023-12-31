#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32130);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_name(english:"Cisco Security Agent Detection");
  script_summary(english:"Determines if Cisco Security Agent is installed");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has an endpoint security application
installed."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Cisco Security Agent, an endpoint security application system is
installed on the remote Windows host."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.cisco.com/c/en/us/products/security/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:security_agent");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

port = kb_smb_transport();
appname = 'Cisco Security Agent';

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Cisco\CSAgent\BaseDir";
path = get_registry_value(handle:hklm, item:key);

RegCloseKey(handle:hklm);
if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
close_registry(close:FALSE);

exe = path + "\bin\okclient.exe";
ver = hotfix_get_fversion(path:exe);
hotfix_check_fversion_end();

if (ver['error'] == HCF_NOENT) audit(AUDIT_UNINST, appname);
else if (ver['error'] != HCF_OK) audit(AUDIT_VER_FAIL, exe);

version = join(ver['value'], sep:'.');
kb_base = 'SMB/Cisco Security Agent/';
set_kb_item(name:kb_base + 'Path', value:path);
set_kb_item(name:kb_base + 'Version', value:version);

register_install(
  app_name:appname,
  vendor : 'Cisco',
  product : 'Security Agent',
  path:path,
  version:version,
  cpe:"cpe:/a:cisco:security_agent");

report_installs(app_name:appname, port:port);

