#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18431);
  script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");

  script_name(english:"AOL Instant Messenger (AIM) Software Detection");
  script_summary(english:"Detects AOL Instant Messenger");

 script_set_attribute(attribute:"synopsis", value:"The remote Windows host contains an instant-messaging application.");
 script_set_attribute(attribute:"description", value:
"AOL Instant Messenger (AIM) is installed on the Windows host. AIM is
an instant-messaging application.");
 script_set_attribute(attribute:"see_also", value:"https://www.aol.com/");
 script_set_attribute(attribute:"solution", value:
"Make sure the use of this program is in accordance with your corporate
security policy.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/08");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:aim_sniff:aim_sniff");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_set_attribute(attribute:"agent", value:"windows");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");

#if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
port = kb_smb_transport();
login = kb_smb_login();
pass = kb_smb_password();
domain = kb_smb_domain();

# Connect to the remote registry.
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) exit(0);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(0);
}

# Open the key used for AIM.
key = "SOFTWARE\America Online\AOL Instant Messenger";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  # Grab installed version(s) of AIM (listed as subkeys of 'key_h').
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    entries[i] = RegEnumKey(handle:key_h, index:i);
  }
}
else
{
  key = 'SOFTWARE\\AOL\\AIM';
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    info = RegQueryInfoKey(handle:key_h);
    for (i=0; i<info[1]; ++i)
    {
      version = RegEnumKey(handle:key_h, index:i);
      if ( !version )
        continue;
      key2_h = RegOpenKey(handle:hklm, key:string( key, '\\', version ), mode:MAXIMUM_ALLOWED);
      if ( !key2_h )
        continue;
      res = RegQueryValue(handle:key2_h, item:"imAppVer");
      if ( res && res[ 0 ] )
        entries[i] = res[ 1 ];
      RegCloseKey(handle:key2_h);
    }
    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
NetUseDel();

if( isnull( entries ))
{
  exit(0, 'AIM not detected.' );
}

# Determine the newest version.
got_max = 0;
max = split("0.0.0.0", sep:".", keep:FALSE);
foreach entry (entries)
{
  if (ereg(pattern:"[0-9]*\.[0-9]*\.[0-9]*", string:entry))
  {
    ver = split(entry, sep:'.', keep:0);
    if  ( int(ver[0]) > int(max[0]) ||
          (int(ver[0]) == int(max[0]) && int(ver[1]) > int(max[1])) ||
          (int(ver[0]) == int(max[0]) && int(ver[1]) == int(max[1]) && int(ver[2]) > int(max[2]))
        )
    {
      got_max = 1;
      max[0] = ver[0];
      max[1] = ver[1];
      max[2] = ver[2];
    }
  }
  else if ( ereg(pattern:"ver[0-9]*_[0-9]*_[0-9]*_[0-9]*", string:entry) )
  {
    ver = split( substr( entry, 3), sep:'_', keep:0);
    if  ( int(ver[0]) >= int(max[0]) &&
          int(ver[1]) >= int(max[1]) &&
          int(ver[2]) >= int(max[2]) &&
          int(ver[3]) >= int(max[3])
        )
    {
      got_max = 1;
      max = ver;
    }
  }
}


# Update KB and report findings.
if (got_max)
{
  ver = '';
  foreach i ( max )
    ver += i + '.';

  ver = substr( ver, 0, strlen( ver ) - 2 );

  set_kb_item(name:"AIM/version", value:ver);

  report = strcat(
    'AOL Instant Messenger version ', ver, ' is installed on the remote host.\n'
  );
  security_note(port:port, extra:report);
}
