#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55650);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_name(english:"SAP GUI Detection");
  script_summary(english:"Checks for the presence of SAP GUI.");

  script_set_attribute(attribute:"synopsis", value:"SAP GUI is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host has an installation of SAP GUI, which is the universal
client for accessing SAP applications.");

  script_set_attribute(attribute:"see_also", value:"http://www.sdn.sap.com/irj/sdn/sap-gui");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/22");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:gui");
  script_set_attribute(attribute:"plugin_type", value:"local");
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

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");
include("install_func.inc");

app = "SAP GUI";

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

# Try to connect to server.


if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# Connect to IPC share.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Failed to connect to IPC share.");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Failed to connect to the remote registry.");
}

# Get the location of the SAP GUI installation.
base = NULL;

key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\SAP\SAP Shared", mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"SAPsysdir");
  if (!isnull(item))
    base = ereg_replace(string:item[1], pattern:"^(.+)\\$", replace:"\1");

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(base))
{
  NetUseDel();
  exit(0, "SAP GUI is not installed on the remote host.");
}

# Split the software's location into components.
share = ereg_replace(string:base, pattern:"^([A-Za-z]):.*", replace:"\1$");
dir = ereg_replace(string:base, pattern:"^[A-Za-z]:(.*)", replace:"\1");
file = "\SAPgui.exe";
NetUseDel(close:FALSE);

# Connect to the share software is installed on.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Failed to connect to " + share + " share.");
}

# Try and read the main executable.
fh = FindFile(
  file               : dir + file,
  desired_access     : GENERIC_READ,
  file_attributes    : FILE_ATTRIBUTE_NORMAL,
  share_mode         : FILE_SHARE_READ,
  create_disposition : OPEN_EXISTING
);
if (isnull(fh))
{
  NetUseDel();
  exit(0, "Failed to open '" + base + file + "'.");
}

# Extract version information from the main executable.
iver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

if (isnull(iver))
  exit(1, "Failed to extract the file version from '" + base + file + "'.");
ver = join(iver, sep:".");

# Save the installation information for later.
set_kb_item(name:"SMB/SAP_GUI/Installed", value:TRUE);
set_kb_item(name:"SMB/SAP_GUI/Path", value:base);
set_kb_item(name:"SMB/SAP_GUI/Version", value:ver);

register_install(
  app_name:app,
  vendor : 'SAP',
  product : 'GUI',
  path:base,
  version:ver,
  cpe:"cpe:/a:sap:gui");

# Report findings.
report_installs(app_name:app, port:port);

