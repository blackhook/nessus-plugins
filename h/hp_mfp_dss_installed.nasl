#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46675);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/06");

  script_name(english:"HP MFP Digital Sending Software Detection");
  script_summary(english:"Checks for HP MFP Digital Sending Software");

  script_set_attribute(attribute:"synopsis", value:
"HP MFP Digital Sending Software is installed on the remote Windows
host.");

  script_set_attribute(attribute:"description", value:
"The remote Windows host contains HP MFP Digital Sending Software, an
application that enables an HP Multifunction Peripheral (MFP) to send
scanned documents directly to several types of destinations.");
  # http://web.archive.org/web/20090105035734/http://h20392.www2.hp.com/portal/swdepot/displayProductInfo.do?productNumber=T1936AA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fef6b4c5");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:multifunction_peripheral_digital_sending_software");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

app = "HP MFP Digital Sending Software";

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");

# Connect to the appropriate share.
name    = kb_smb_name();
port    = kb_smb_transport();

login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

path=NULL;
key = "SOFTWARE\Hewlett-Packard\HP Digital Sender Module";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h);
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}

if (isnull(path))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0, "HP MFP Digital Sending Software is not installed.");
}

# Get the version from the executable itself.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\hpbs2e.exe", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to " + share + " share.");
}

fh = CreateFile(
  file:exe,
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
else
{
  NetUseDel();
  exit(0, "Failed to open '"+path+"\hpbs2e.exe'.");
}
NetUseDel();

# Save and report the version number and installation path.
if (!isnull(ver))
{
  version = join(ver, sep:'.');

  set_kb_item(name:"SMB/HP_MFP_DSS/Path", value:path);
  set_kb_item(name:"SMB/HP_MFP_DSS/Version", value:version);

  register_install(
    app_name:app,
    path:path,
    vendor:"HP",
    product:"Multifunction Peripheral Digital Sending Software",
    version:version,
    cpe:"cpe:/a:hp:multifunction_peripheral_digital_sending_software");

  report_installs(app_name:app, port:port);
}
else exit(1, "Failed to get the file version for '"+path+"\hpbs2e.exe'.");
