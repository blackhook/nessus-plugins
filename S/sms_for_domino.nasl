#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55046);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");

  script_xref(name:"IAVT", value:"0001-T-0883");

  script_name(english:"Symantec Mail Security for Domino Installed");
  script_summary(english:"Checks version of Symantec Mail Security for Domino.");

  script_set_attribute(attribute:"synopsis", value:"The remote host has an antivirus software installed.");
  script_set_attribute(attribute:"description", value:
"Symantec Mail Security for Domino, a commercial antivirus software
that offers mail protection against viruses, spam and other security
threats is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://support.symantec.com/content/unifiedweb/en_US/product.mail-security-for-domino.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/10");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:mail_security");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_inventory", value:"True");
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

# Get the location the software was installed at.
base = NULL;

key1 = "SOFTWARE\Symantec\Symantec Mail Security for Domino\Install";
key1_h = RegOpenKey(handle:hklm, key:key1, mode:MAXIMUM_ALLOWED);
if (!isnull(key1_h))
{
  info = RegQueryInfoKey(handle:key1_h);
  for (i = 0; i < info[1]; i++)
  {
    # Ignore subkeys that don't look like version numbers.
    version = RegEnumKey(handle:key1_h, index:i);
    if (!strlen(version) || version !~ "^[0-9.]+$") continue;

    # Open up key for software's installed version.
    key2 = key1 + "\" + version;
    key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
    if (!isnull(key2_h))
    {
      item = RegQueryValue(handle:key2_h, item:"InstallDir");
      if (!isnull(item))
        base = ereg_replace(string:item[1], pattern:"^(.+)\\$", replace:"\1");
      RegCloseKey(handle:key2_h);
    }

    if (!isnull(base)) break;
  }
  RegCloseKey(handle:key1_h);
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if (isnull(base))
{
  NetUseDel();
  exit(0, "Symantec Mail Security for Domino is not installed on the remote host.");
}

# Split the software's location into components.
share = ereg_replace(string:base, pattern:"^([A-Za-z]):.*", replace:"\1$");
dir = ereg_replace(string:base, pattern:"^[A-Za-z]:(.*)", replace:"\1");
file = "\PAS\Bin\smsdkick.exe";

# Connect to the share software is installed on.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Failed to connect to " + share + " share.");
}

# Find the version string in the executable.
version = NULL;
fh = CreateFile(
  file:dir + file,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if (!isnull(fh))
{
  version = GetFileVersion(handle:fh);
  if (!isnull(version))
    version = join(version, sep:".");
  CloseFile(handle:fh);
}

if (isnull(version))
{
  NetUseDel();
  exit(1, "Failed to extract the version number from " + base + file + ".");
}

# Clean up.
NetUseDel();

# Report our findings.
set_kb_item(name:"SMB/SMS_Domino/Installed", value:TRUE);
set_kb_item(name:"SMB/SMS_Domino/Path", value:base);
set_kb_item(name:"SMB/SMS_Domino/Version", value:version);

# global kb for optimization
replace_kb_item(name:"Symantec_Mail_Security/Installed", value:TRUE);

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + base +
    '\n  Installed version : ' + version +
    '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
