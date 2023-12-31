#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description) {
  script_id(20846);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"BitTornado Detection");

  script_set_attribute(attribute:"synopsis", value:
"There is a peer-to-peer file sharing application installed on the
remote Windows host.");
  script_set_attribute(attribute:"description", value:
"BitTornado is installed on the remote Windows host. BitTornado is a
peer-to-peer file sharing application that supports the BitTorrent
protocol.

Make sure the use of this program fits with your corporate security
policy.");
  script_set_attribute(attribute:"see_also", value:"http://www.bittornado.com/");
  script_set_attribute(attribute:"solution", value:
"Remove this software if its use does not match your corporate security
policy.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:bittornado:bittornado");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2006-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");


# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
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
if (isnull(hklm)) {
  NetUseDel();
  exit(0, "cannot connect to the remote registry");
}


# Determine if it's installed.
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\btdownloadgui.exe";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) exe = value[1];
  RegCloseKey(handle:key_h);
}
if (isnull(exe) && thorough_tests) {
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\BitTornado\DisplayIcon";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
    value = RegQueryValue(handle:key_h, item:"DisplayIcon");
    if (!isnull(value)) exe = value[1];
    RegCloseKey(handle:key_h);
  }
}
if (isnull(exe) && thorough_tests) {
  key = "SOFTWARE\Classes\bittorrent\shell\open\command";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) {
      # nb: the exe itself appears in quotes.
      exe = ereg_replace(pattern:'^"([^"]+)".*', replace:"\1", string:value[1]);
    }
    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);


# If it is...
if (exe) {
  # Locate BitTornado's library.zip.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:exe);
  zip =  ereg_replace(pattern:"^[A-Za-z]:(.*)\\[^\\]+\.exe", replace:"\1\library.zip", string:exe);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1) {
    NetUseDel();
    exit(0, "cannot connect to the remote share");
  }

  fh = CreateFile(
    file:zip,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh)) {
    NetUseDel();
    exit(0, "cannot read '"+zip+"'" );
  }

  # Find start / size of zip file's central directory.
  #
  # nb: see <http://www.pkware.com/documents/casestudies/APPNOTE.TXT>.
  set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
  fsize = GetFileSize(handle:fh);
  chunk = 200;                         # arbitrary, but works pretty well
  if (fsize > chunk) {
    data = ReadFile(handle:fh, length:chunk, offset:fsize-chunk);
    if (data) {
      eocdr = strstr(data, raw_string(0x50, 0x4b, 0x05, 0x06));
      if (eocdr && strlen(eocdr) > 20) {
        dir_size = getdword(blob:eocdr, pos:12);
        dir_ofs = getdword(blob:eocdr, pos:16);
      }
    }
  }

  # Find start of __init__.pyc from zip file's central directory.
  if (dir_ofs && dir_size) {
    data = ReadFile(handle:fh, length:dir_size, offset:dir_ofs);
    if (data) {
      fname = stridx(data, "BitTornado/__init__.pycPK");
      if (fname >= 0) ofs = getdword(blob:data, pos:fname-4);
    }
  }

  # Read a bit of __init__.pyc from within the zip file.
  if (ofs) {
    data = ReadFile(handle:fh, length:512, offset:ofs);
    if (data) {
      # Pull version out from a Python string.
      blob = strstr(data, "BitTornados");
      if (blob) blob = blob - "BitTornados";
      else {
        # older versions include "BitTornado" in the version string.
        idx = stridx(data, "(BitTornado)s");
        if (idx >= 0) {
          blob = strstr(substr(data, idx-30), "s");
          if (blob) blob = blob - "s";
        }
      }
      if (blob) {
        length = getdword(blob:blob, pos:0);
        if (length) {
          ver = substr(blob, 4, 4-1+length);
        }
      }
    }
  }
  CloseFile(handle:fh);

  # If the version number's available, save and report it.
  if (!isnull(ver)) {
    set_kb_item(name:"SMB/BitTornado/Version", value:ver);

    report = "Version " +  ver +  ' of BitTornado is installed as :\n' +  "  " +  exe +  '\n';

    security_report_v4(port:kb_smb_transport(), extra:report, severity:SECURITY_NOTE);
  }
}


# Clean up.
NetUseDel();
