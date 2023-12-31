#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58272);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/31");

  script_name(english:"FlexNet License Server Installed");
  script_summary(english:"Checks for FlexNet License Server");

  script_set_attribute(attribute:"synopsis", value:
"A license management application is installed on the remote Windows
host.");
  script_set_attribute(attribute:"description", value:
"Flexera FlexNet License Server, a license management application, is
installed on the remote Windows host.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b32c8d56");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:flexerasoftware:flexnet_publisher");
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

include('global_settings.inc');
include('misc_func.inc');
include('smb_func.inc');
include("audit.inc");
include("install_func.inc");

app = "FlexNet License Server";
get_kb_item_or_exit('SMB/Registry/Enumerated');

# Connect to the appropriate share.
name   = kb_smb_name();
port   = kb_smb_transport();
#if (!get_port_state(port)) exit(0, 'Port '+port+' is not open.');
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(1, 'Failed to open a socket on port '+port+'.');

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
if (rc != 1)
{
  NetUseDel();
  exit(1, 'Can\'t connect to IPC$ share.');
}

# Connect to the remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, 'Can\'t connect to the remote registry.');
}

path = NULL;
service = NULL;
key = 'SOFTWARE\\FLEXlm License Manager\\FLEXlm License Manager';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:'Lmgrd');
  if (!isnull(item)) path = item[1] - '\\lmgrd.exe';

  # Get the service name
  item = RegQueryValue(handle:key_h, item:'Service');
  if (!isnull(item)) service = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, 'FlexNet License Server is not installed on the remote host.');
}

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
exe   = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\lmgrd.exe', string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, 'Can\'t connect to '+share+' share.');
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if (isnull(fh))
{
  NetUseDel();
  exit(0, 'Couldn\'t open \''+(share-'$')+':'+exe+'\'.');
}

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

if (isnull(ver)) exit(1, 'Couldn\'t get the version of \''+(share-'$')+':'+exe+'\'.');
version = join(ver, sep:'.');

set_kb_item(name:'SMB/Flexera FlexNet License Server/Version', value:version);
set_kb_item(name:'SMB/Flexera FlexNet License Server/Path', value:path);
set_kb_item(name:'SMB/Flexera FlexNet License Server/Service', value:service);

register_install(
  vendor:"Flexera Software",
  product:"FlexNet Publisher",
  app_name:app,
  path:path,
  version:version,
  extra:make_array("Service", service),
  cpe:"cpe:/a:flexerasoftware:flexnet_publisher"
);

report_installs(app_name:app, port:port);

