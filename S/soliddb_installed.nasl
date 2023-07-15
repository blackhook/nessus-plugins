#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(53811);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_name(english:"IBM solidDB Detection (local check)");
  script_summary(english:"Checks for solidDB");

  script_set_attribute(attribute:"synopsis", value:"The remote host has a database server installed.");

  script_set_attribute(attribute:"description", value:
"The remote Windows host is running IBM solidDB, an in-memory database
application.");

  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/software/data/soliddb-departure/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:soliddb");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('smb_hotfixes.inc');
include('smb_func.inc');
include('misc_func.inc');
include("audit.inc");
include("install_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');

# Get the install path
name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

app = "IBM solidDB";

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
if (rc != 1)
{
  NetUseDel();
  exit(1,'Can\'t connect to IPC$ share.');
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1,'Can\'t connect to the remote registry.');
}

# First check the app paths registry for solidDB
paths = make_list();

key = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\solid.exe';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  # If SolidDB is installed...
  item = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(item))
    paths = make_list(paths, item[1]);

  RegCloseKey(handle:key_h);
}


# We can have multiple installs, so check the Uninstall hive to be sure.
list = get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
if (isnull(list)) exit(1, 'Could not get Uninstall KB.');

item = NULL;
installstrings = make_list();
foreach name (keys(list))
{
  prod = list[name];
  if (prod && "solidDB " >< prod)
  {
    item = ereg_replace(pattern:'^SMB\\/Registry\\/HKLM\\/(SOFTWARE\\/Microsoft\\/Windows\\/CurrentVersion\\/Uninstall\\/.+)\\/DisplayName$', replace:'\\1', string:name);
    installstrings = make_list(installstrings, str_replace(find:'/', replace:'\\', string:item));
  }
}

# Build an array of installs
if (max_index(installstrings) > 0)
{
  for (i=0; i<max_index(installstrings); i++)
  {
    key_h = RegOpenKey(handle:hklm, key:installstrings[i], mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      # If SolidDB is installed...
      item = RegQueryValue(handle:key_h, item:'InstallLocation');
      if (!isnull(item))
        paths = make_list(paths, item[1] + '\\bin');

      RegCloseKey(handle:key_h);
    }
  }
}
RegCloseKey(handle:hklm);

if (max_index(paths) == 0)
{
  NetUseDel();
  exit(0, 'solidDB does not appear to be installed on the remote host.');
}
paths = list_uniq(paths);


# Loop through and check each install.
installs = 0;

foreach path (paths)
{
  version = NULL;
  share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
  exe =  ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\solid.exe', string:path);

  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, 'Can\'t connect to '+ share + ' share.');
  }

  fh = CreateFile(
    file:exe,
  	desired_access:GENERIC_READ,
  	file_attributes:FILE_ATTRIBUTE_NORMAL,
  	share_mode:FILE_SHARE_READ,
	  create_disposition:OPEN_EXISTING
  );
  if (isnull(fh)) continue;

  installs++;
  ver = GetFileVersion(handle:fh);
  if (isnull(ver))
  {
    version = 'Unknown';
    debug_print('Couldn\'t get the version of '+path+'\\solid.exe.');
  }
  else
  {
    version = join(ver, sep:'.');
    set_kb_item(name:'SMB/solidDB/'+version+'/path', value:path);
  }
  ret = GetFileVersionEx(handle:fh);
  CloseFile(handle:fh);
  if (!isnull(ret))
  {
    timestamp = ret['dwTimeDateStamp'];
    set_kb_item(name:'SMB/solidDB/'+version+'/timestamp', value:timestamp);
  }

  register_install(
    app_name:app,
    vendor : 'IBM',
    product : 'solidDB',
    path:path,
    version:version,
    extra:make_array('Timestamp', timestamp),
    cpe:"cpe:/a:ibm:soliddb");
}
NetUseDel();

if (installs)
{
  set_kb_item(name:'SMB/solidDB/installed', value:TRUE);
  report_installs(app_name:app, port:port);
  exit(0);
}
else exit(0, 'No solidDB installs were detected on the remote host.');
