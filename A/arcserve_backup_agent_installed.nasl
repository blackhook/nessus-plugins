#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62810);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_name(english:"CA ARCserve Backup Agent Installed");
  script_summary(english:"Checks for CA ARCserve Backup Agent");

  script_set_attribute(attribute:"synopsis", value:"A backup agent is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"CA ARCserve Backup Agent, a backup agent for CA ARCserve Backup, is
installed on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"https://www.arcserve.com/data-protection-solutions/arcserve-replication-high-availability/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:arcserve_backup_client_agent_for_windows");
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

registry_init();
port = kb_smb_transport();
appname = 'CA ARCserve Backup Agent';

hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\ComputerAssociates\CA ARCserve Backup\InstallPath\NTAgent";
path = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
close_registry(close:FALSE);

dll = path + "\ntagent.dll";
ver = hotfix_get_fversion(path:dll);
hotfix_check_fversion_end();

if (ver['error'] == HCF_NOENT)
  audit(AUDIT_UNINST, appname);
else if (ver['error'] != HCF_OK)
  audit(AUDIT_VER_FAIL, dll);

version = join(sep:'.', ver['value']);

set_kb_item(name:'SMB/CA ARCserve Backup/Installed', value:TRUE);
set_kb_item(name:'SMB/'+appname+'/Path', value:path);
set_kb_item(name:'SMB/'+appname+'/Version', value:version);

register_install(
  app_name:appname,
  vendor : 'CA',
  product : 'Arcserve Backup Client Agent',
  path:path,
  version:version,
  target_sw : 'Windows',
  cpe:"cpe:/a:ca:arcserve_backup_client_agent_for_windows");

report_installs(app_name:appname, port:port);

