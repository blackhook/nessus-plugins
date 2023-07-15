#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29729);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"iMesh P2P Client Detection");
  script_summary(english:"Checks for iMesh");

 script_set_attribute(attribute:"synopsis", value:
"There is a peer-to-peer file sharing application installed on the
remote Windows host.");
 script_set_attribute(attribute:"description", value:
"iMesh is installed on the remote Windows host. iMesh is a peer-to-
peer file sharing application.

Make sure the use of this program fits with your corporate security
policy.");
 script_set_attribute(attribute:"see_also", value:"http://www.imesh.com/");
 script_set_attribute(attribute:"solution", value:
"Remove this software if its use does not match your corporate security
policy.");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"agent", value:"windows");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/19");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:imesh.com:imesh");
script_set_attribute(attribute:"asset_inventory", value:"True");
script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2007-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");
include("misc_func.inc");
include("install_func.inc");

app = "iMesh P2P Client";

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Make sure it's installed.
exe = NULL;

key = "SOFTWARE\Classes\Applications\iMesh.exe\shell\open\command";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[0]; ++i) {
    value = RegEnumValue(handle:key_h, index:i);
    if (!isnull(value))
    {
      subkey = value[1];

      # Get the install path.
      item = RegQueryValue(handle:key_h, item:subkey);
      if (!isnull(item))
      {
        exe = item[1];
        exe = ereg_replace(pattern:'^"([^"]+)".*$', replace:"\1", string:exe);
      }
    }
    if (exe && exe =~ "^[A-Za-z]:.+") break;
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(exe))
{
  NetUseDel();
  exit(0);
}


# Grab the file version.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:exe);
exe2 = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:exe);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:exe2,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();


# Check the version number.
if (!isnull(ver))
{
  path = ereg_replace(pattern:"^(.*)\\[^\\]+\.exe", replace:"\1", string:exe, icase:TRUE);
  version = ver[0] +  "." +  ver[1] +  "." +  ver[2] +  "." +  ver[3];

  set_kb_item(name:"SMB/iMesh/Path",    value:path);
  set_kb_item(name:"SMB/iMesh/Version", value:version);

  register_install(
    vendor:"iMesh.com",
    product:"iMesh",
    app_name:app,
    path:path,
    version:version,
    cpe: "cpe:/a:imesh.com:imesh");

  report_installs(app_name:app, port:port);
}
