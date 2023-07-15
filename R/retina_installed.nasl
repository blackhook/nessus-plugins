#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39807);
  script_version("1.13");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/06");

  script_name(english:"eEye Retina Network Security Scanner Detection");
  script_summary(english:"Checks the registry for a Retina install");

  script_set_attribute(attribute:"synopsis", value:"A network scanner is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:"Retina Network Security Scanner is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://www.beyondtrust.com/products/retina-network-security-scanner/");
  script_set_attribute(attribute:"solution", value:
"Ensure that use of this software is in agreement with your
organization's acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:eeye:retina_wifi_scanner");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");
include("install_func.inc");

app = "eEye Retina Network Security Scanner";

# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0, "Remote registry has not been enumerated.");

port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

path = NULL;
key = "SOFTWARE\eEye\Retina";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"Path");
  if (item) path = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "No evidence of Retina found in the registry.");
}
NetUseDel(close:FALSE);

# Try to access Retina.exe from the Retina installation directory, in order to
# make sure Retina is actually installed where the registry thinks it is
share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
exe = ereg_replace(
  pattern:'^[A-Za-z]:(.*)',
  replace:"\1\Retina.exe",
  string:path
);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

# Grab the version number if the file was opened successfully.  Otherwise,
# bail out.
ver = NULL;
if (fh)
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
  NetUseDel();
}
else
{
  NetUseDel();
  exit(1, "Unable to access Retina file: " + exe);
}

if (ver)
{
  retina_ver = ver[0] +  "." +  ver[1] +  "." +  ver[2] +  "." +  ver[3];
  set_kb_item(name:"SMB/Retina/Version", value:retina_ver);
  set_kb_item(name:"SMB/Retina/" + retina_ver, value:path);

  register_install(
    vendor:"eEye",
    product:"Retina Network Security Scanner",
    app_name:app,
    path:path,
    version:retina_ver,
    cpe: "cpe:/a:eeye:retina_wifi_scanner");

  report_installs(app_name:app, port:port);
  exit(0);
}
else exit(1, "Error retrieving version number from Retina file: " + exe);
