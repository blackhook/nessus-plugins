#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34205);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/06");

  script_xref(name:"IAVT", value:"0001-T-0702");

  script_name(english:"Pidgin Detection (Windows)");
  script_summary(english:"Checks for Pidgin on Windows");

 script_set_attribute(attribute:"synopsis", value:
"There is an instant messaging client installed on the remote Windows
host.");
 script_set_attribute(attribute:"description", value:
"Pidgin, an open source, multi-protocol instant messaging client, is
installed on the remote host.");
 script_set_attribute(attribute:"see_also", value:"http://pidgin.im/");
 script_set_attribute(attribute:"solution", value:
"Make sure use of this program fits with your organization's security
policy.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/15");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:pidgin:pidgin");
script_set_attribute(attribute:"asset_inventory", value:"True");
script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
script_set_attribute(attribute:"agent", value:"windows");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");
include("misc_func.inc");
include("install_func.inc");

app = "Pidgin";

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "KB 'SMB/Registry/Enumerated' not set to TRUE.");


function display_dword (dword, nox)
{
 local_var tmp;

 if (isnull(nox) || (nox == FALSE))
   tmp = "0x";
 else
   tmp = "";

 return tmp + toupper(
                  hexstr(
                    raw_string(
                               (dword >>> 24) & 0xFF,
                               (dword >>> 16) & 0xFF,
                               (dword >>> 8) & 0xFF,
                               dword & 0xFF
                              )
                        )
                      );
}


# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
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


# Determine where it's installed.
path = NULL;

key = "SOFTWARE\pidgin";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(item))
  {
    path = item[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Determine its version from the executable itself.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\pidgin.exe", string:path);
NetUseDel(close:FALSE);

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

version = NULL;
version_ui = NULL;

if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  version = ver[0] +  "." +  ver[1] +  "." +  ver[2] +  "." +  ver[3];

  ret = GetFileVersionEx(handle:fh);
  if (!isnull(ret)) children = ret['Children'];
  if (!isnull(children))
  {
    varfileinfo = children['VarFileInfo'];
    if (!isnull(varfileinfo))
    {
      translation =
        (get_word (blob:varfileinfo['Translation'], pos:0) << 16) +
        get_word (blob:varfileinfo['Translation'], pos:2);
      translation = tolower(display_dword(dword:translation, nox:TRUE));
    }
    stringfileinfo = children['StringFileInfo'];
    if (!isnull(stringfileinfo) && !isnull(translation))
    {
      data = stringfileinfo[translation];
      if (!isnull(data)) version_ui = data['FileVersion'];
      else
      {
        data = stringfileinfo[toupper(translation)];
        if (!isnull(data)) version_ui = data['ProductVersion'];
      }
    }
  }

  CloseFile(handle:fh);
}
NetUseDel();


# Save and report the version number and installation path.
if (!isnull(version) && !isnull(path))
{
  kb_base = "SMB/Pidgin";
  set_kb_item(name:kb_base+"/Path", value:path);
  set_kb_item(name:kb_base+"/Version", value:version);

  if (!isnull(version_ui))
  {
    set_kb_item(name:kb_base+"/Version_UI", value:version_ui);
    version_report = version_ui;
  }
  else version_report = version;

  register_install(
    vendor:"Pidgin",
    product:"Pidgin",
    app_name:app,
    path:path,
    version:version,
    display_version:version_ui,
    cpe:"cpe:/a:pidgin:pidgin");

  report_installs(app_name:app, port:port);
}
