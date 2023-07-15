#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


include('deprecated_nasl_level.inc');
include("compat.inc");


if (description)
{
  script_id(55817);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/06");

  script_name(english:"HCL BigFix Client Installed (Windows)");
  script_summary(english:"Checks to see if the app is installed");

  script_set_attribute(attribute:"synopsis", value:"An endpoint management client is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"HCL BigFix Client (formerly IBM Tivoli Endpoint Manager Client, BigFix Enterprise Suite
Client) is installed on the remote Windows host. This software is used
to facilitate management of the system.");
  script_set_attribute(attribute:"see_also", value:"https://www.hcltechsw.com/bigfix");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hcltech:bigfix_platform");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:bigfix_platform");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:endpoint_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_endpoint_manager");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ibm:tivoli_endpoint_manager_client");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("install_func.inc");
include("smb_reg_query.inc");

name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

app = "HCL BigFix Client";


if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to the remote registry.");
}

# even the rebranded IBM version of the software uses this key
var key = "SOFTWARE\BigFix\EnterpriseClient";
var key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
var path = NULL;
var values_key = hotfix_append_path(path:key, value:'GlobalOptions');
var values = ['ServerId', 'ServerName', 'ComputerId', 'GatherUrl'];
var extra = {};

if (!isnull(key_h))
{
  wow_chk = RegQueryValue(handle:key_h, item:"Version");
  if (isnull(wow_chk))
  {
    key = ereg_replace(pattern:"^SOFTWARE\\(.*)", string:key, replace:"SOFTWARE\\Wow6432Node\\\1", icase:TRUE);
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  }
}
{
  ret = RegQueryValue(handle:key_h, item:'EnterpriseClientFolder');
  if (!isnull(ret))
    path = ret[1];

  extra = get_values_from_key(handle:hklm, entries:values, key:values_key);
  extra['ComputerId'] = get_raw_ascii_hex_values(val:extra['ComputerId']);
  extra['ComputerId'] = extra['ComputerId']['hex'];
  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, 'TEM Client doesn\'t appear to be installed.');
}

var share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
var exe = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\BESClientUI.exe', string:path);

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

ver = NULL;
exe_found = FALSE;

if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
  exe_found = TRUE;
}

NetUseDel();

if (!exe_found)
  exit(0, 'File not found: ' + path + '\\BESClientUI.exe');
if (isnull(ver))
  exit(1, 'Error getting version from ' + path + '\\BESClientUI.exe');

version = join(ver, sep:'.');

set_kb_item(name:'SMB/ibm_tem_client/Path', value:path);
set_kb_item(name:'SMB/ibm_tem_client/Version', value:version);

if(!empty_or_null(extra['ComputerId'])) report_xml_tag(tag:'bigfix_computerid', value:extra['ComputerId']);
if(!empty_or_null(extra['GatherUrl'])) report_xml_tag(tag:'bigfix_gatherurl', value:extra['GatherUrl']);

register_install(
  vendor:"HCLTech",
  product:"BigFix Platform",
  app_name:app,
  path:path,
  version:version,
  extra:extra,
  cpe:"cpe:/a:hcltech:bigfix_platform");

report_installs(app_name:app, port:port);

