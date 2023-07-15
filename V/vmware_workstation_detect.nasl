#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26201);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/06");

  script_xref(name:"IAVT", value:"0001-T-0744");

  script_name(english:"VMware Workstation Detection");
  script_summary(english:"Detects if VMware Workstation is installed");

  script_set_attribute(attribute:"synopsis", value:"An OS Virtualization application is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"VMware Workstation, an OS virtualization solution for Desktops and
Laptops that allows the running of multiple operating systems on the
same host, is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/products/workstation-pro.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');
appname = "VMware Workstation";
ver = NULL;

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\VMware, Inc.\VMware Workstation\InstallPath";

path = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);
if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
else close_registry(close:FALSE);

path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
pver = hotfix_get_pversion(path:path + "\vmware.exe");
err_res = hotfix_handle_error(
  error_code   : pver['error'],
  file         : path + "\vmware.exe",
  appname      : appname,
  exit_on_fail : FALSE
);

if (
   !isnull(pver['value'])
   &&
   "e.x.p " >!< pver['value'] # Indicator of unusable pversion
   &&
   (isnull(err_res) || !err_res)
) ver = join(pver['value'], sep:".");
else ver = NULL;

# Try for better version
if (isnull(ver))
{
  fver = hotfix_get_fversion(path:path + "\vmware.exe");
  err_res = hotfix_handle_error(
    error_code   : fver['error'],
    file         : path + "\vmware.exe",
    appname      : appname,
    exit_on_fail : TRUE # second ver-grab fail; just exit
  );

  if (!isnull(fver['value']) && (isnull(err_res) || !err_res))
    ver = join(fver['value'], sep:".");
  else
    ver = NULL;
}
hotfix_check_fversion_end();

# Extract version info
if (!isnull(ver))
{
  matches = pregmatch(string:ver, pattern:"^([0-9.]+).*$", icase:TRUE);
  if (isnull(matches)) ver = NULL;
  else ver = matches[1];
}

if (isnull(ver)) audit(AUDIT_VER_FAIL, path + "\vmware.exe");

set_kb_item(name:"VMware/Workstation/Version", value:ver);
set_kb_item(name:"VMware/Workstation/Path", value:path);

register_install(
  vendor:"VMware",
  product:"Workstation",
  app_name:appname,
  path:path,
  version:ver,
  cpe:"cpe:/a:vmware:workstation"
);

port = kb_smb_transport();

report_installs(app_name:appname, port:port);

