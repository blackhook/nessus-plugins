#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125835);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_name(english:"Microsoft Remote Desktop Connection Installed");
  script_summary(english:"Checks filesystem for Microsoft Remote Desktop Connection (RDP)");

  script_set_attribute(attribute:"synopsis", value:
"A graphical interface connection utility is installed on the remote Windows host");
  script_set_attribute(attribute:"description", value:
"Microsoft Remote Desktop Connection (also known as Remote Desktop Protocol or 
Terminal Services Client) is installed on the remote Windows host.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  # https://docs.microsoft.com/en-us/windows/desktop/TermServ/remote-desktop-protocol
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c33f0e7");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/12");

  script_set_attribute(attribute:"agent", value:"windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:remote_desktop_connection");
  script_set_attribute(attribute:"plugin_type", value:"local");
  
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_com_func.inc');
include('misc_func.inc');
include('install_func.inc');
include('spad_log_func.inc');

if (get_kb_item("SMB/not_windows"))
  audit(AUDIT_HOST_NOT, "Windows");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app = "Microsoft Remote Desktop Connection";

Sys_root = hotfix_get_systemroot();
path = Sys_root + "\\System32\\mstsc.exe";
ver = hotfix_get_fversion(path: path);
hotfix_check_fversion_end();
hotfix_handle_error(
  error_code: ver['error'],
  appname: app,
  file:path,
  exit_on_fail: TRUE);

version = join(ver['value'], sep:'.');

if (!empty_or_null(version))
{
  register_install(
    app_name: app,
    vendor : 'Microsoft',
    product : 'Remote Desktop Connection',
    path: path,
    version: version,
    cpe:"cpe:/a:microsoft:remote_desktop_connection");

  report_installs(app_name:app);
}

exit(0);



