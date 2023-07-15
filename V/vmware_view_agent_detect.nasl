#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63681);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_xref(name:"IAVT", value:"0001-T-0740");

  script_name(english:"VMware View Agent Detection");
  script_summary(english:"Detects if VMware View Agent installed");

  script_set_attribute(attribute:"synopsis", value:"An OS virtual desktop solution is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"VMware View Agent, a component of VMware View which is formerly known
as VMware Virtual Desktop Infrastructure, is installed on the remote
host.  VMware View Agent is installed on desktops to allow the desktop
to communicate with VMware View clients.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/products/horizon.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:view");
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
include("smb_reg_query.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("install_func.inc");

registry_init();
appname = "VMware View Agent";
reg_name = "VMware Horizon Agent";
handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\VMware, Inc.\VMware VDM";
item =  get_values_from_key(handle:handle, key:key, entries:make_list('AgentInstallPath'));
path = item['AgentInstallPath'];
RegCloseKey(handle:handle);
if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
close_registry(close:FALSE);
filePath =  path + "bin\wsnm.exe";

ver = hotfix_get_fversion(path:filePath);
hotfix_check_fversion_end();
if(ver['error'] == HCF_NOENT) audit(AUDIT_UNINST, appname);
else if(ver['error'] != HCF_OK )
{
  audit(AUDIT_VER_FAIL, filePath);
}
version = join(ver['value'], sep:'.');

display_version = UNKNOWN_VER;
entry = hotfix_displayname_in_uninstall_key(pattern:reg_name);
if(entry)
{
  display_version = get_kb_item(entry - "/DisplayName" + "/DisplayVersion");
}
if(empty_or_null(display_version)) display_version = UNKNOWN_VER;


# Agent version can be upped without updating the exe version
# In this case DisplayVersion might provide higher, correct version number
if(ver_compare(ver:version, fix:display_version, strict:FALSE) == -1)
  version = display_version;

port = kb_smb_transport();
set_kb_item(name:"VMware/ViewAgent/Installed", value:TRUE);
set_kb_item(name:"VMware/ViewAgent/Version", value:version);
set_kb_item(name:"VMware/ViewAgent/Path", value:path);

register_install(
  app_name:appname,
  vendor : 'VMware',
  product : 'View',
  path:path,
  version:version,
  cpe:"cpe:/a:vmware:view");

report_installs(app_name:appname, port:port);

