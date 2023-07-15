#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(54953);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_xref(name:"IAVT", value:"0001-T-0915");

  script_name(english:"Cisco AnyConnect Secure Mobility Client Detection");
  script_summary(english:"Checks if the AnyConnect client is installed");

  script_set_attribute(attribute:"synopsis", value:"There is a VPN client installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"Cisco AnyConnect Secure Mobility Client (formerly known as Cisco
AnyConnect VPN Client) is installed on the remote Windows host. This
software can be used for secure connectivity.");
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/ps10884/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_hotfixes.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");
include("install_func.inc");

var install_num = 0;

get_kb_item_or_exit('SMB/Registry/Enumerated');

# Connect to the appropriate share.
var name   = kb_smb_name();
var port   = kb_smb_transport();
var login  = kb_smb_login();
var pass   = kb_smb_password();
var domain = kb_smb_domain();

var app = "Cisco AnyConnect Secure Mobility Client";



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
var rc = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
if (rc != 1)
{
  NetUseDel();
  exit(1, 'Can\'t connect to IPC$ share.');
}

# Connect to remote registry
var hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, 'Can\'t connect to remote registry.');
}

var key_list = make_list('SOFTWARE\\Cisco\\Cisco AnyConnect VPN Client',
                     'SOFTWARE\\Cisco\\Cisco AnyConnect Secure Mobility Client');

var install_paths = make_list();
var key_h, item;
foreach var key (key_list)
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:'InstallPathWithSlash');
    if (!isnull(item))
      append_element(var:install_paths, value:item[1]);
    
    RegCloseKey(handle:key_h);
  }
}

#Look at the registry entries for more recent versions too
key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers";
var subkeys = get_reg_name_value_table(handle:hklm, key:key);
foreach var reg_value (keys(subkeys))
{
  if(reg_value =~ ".*Cisco AnyConnect Secure Mobility Client\\vpnui.exe$")
    append_element(var:install_paths, value:reg_value - 'vpnui.exe');
}

RegCloseKey(handle:hklm);

if (max_index(install_paths) == 0)
{
  NetUseDel();
  exit(0, 'Cisco AnyConnect VPN Client was not detected on the remote host.');
}
else NetUseDel(close:FALSE);

var share, exe, fversion, fh, pversion;
foreach var path (install_paths)
{
  share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
  exe = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1vpnui.exe', string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, 'Can\'t connect to '+share+' share.');
  }

  fversion = NULL;
  pversion = NULL;
  fh = CreateFile(
    file:exe,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (isnull(fh))
  {
    NetUseDel(close:FALSE);
    continue;
  }

  fversion = GetFileVersion(handle:fh);

  if (isnull(fversion))
  {
    CloseFile(handle:fh);
    NetUseDel(close:FALSE);
    continue;
  }
  else
    fversion = join(fversion, sep:'.');

  pversion = GetProductVersion(handle:fh);
  CloseFile(handle:fh);
  NetUseDel(close:FALSE);

  if (!isnull(pversion))
  {
    #product version arrives as a string looking like '9, 2, 1'
    pversion = str_replace(string:pversion, find:' ', replace:'');
    pversion = split(pversion, sep:',', keep:FALSE);
    pversion = join(pversion, sep:'.');
  }
  
  set_kb_item(name:'SMB/cisco_anyconnect/' + install_num + '/path', value:path);
  if(empty_or_null(pversion))
    set_kb_item(name:'SMB/cisco_anyconnect/' + install_num + '/version', value:fversion);
  else set_kb_item(name:'SMB/cisco_anyconnect/' + install_num + '/version', value:pversion);
  register_install(
    app_name:app,
    vendor : 'Cisco',
    product : 'AnyConnect Secure Mobility Client',
    path:path,
    version:fversion,
    display_version:pversion,
    cpe:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  install_num++;
}

NetUseDel();

if(install_num)
{
  set_kb_item(name:'SMB/cisco_anyconnect/Installed', value:TRUE);
  set_kb_item(name:'SMB/cisco_anyconnect/NumInstalled', value:install_num);
  report_installs(app_name:app, port:port);
  exit(0);
}
