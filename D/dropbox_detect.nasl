#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(35717);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/31");

  script_name(english:"Dropbox Software Detection");
  script_summary(english:"Checks Windows Registry for Dropbox");

  script_set_attribute(attribute:"synopsis", value:"There is a file synchronization application on the remote host.");
  script_set_attribute(attribute:"description", value:
"Dropbox is installed on the remote host. Dropbox is an application for
storing and synchronizing files between computers, possibly outside
the organization.");
  script_set_attribute(attribute:"see_also", value:"https://www.dropbox.com/");
  script_set_attribute(attribute:"solution", value:
"Ensure that use of this software agrees with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dropbox:dropbox");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139,445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");
include("install_func.inc");
include("spad_log_func.inc");

app = "Dropbox Software";

# Walk up the path and check if each directory
# in the path is a reparse point
function reparse_points_exist_in_path(check_path)
{
  local_var check_ret;
  while (check_path != '\\' && strlen(check_path) > 0)
  {
    check_ret = FindFirstFile(pattern:check_path);

    # Look for reparse point directories
    # in file attributes
    if(!isnull(check_ret[2]) &&
      # FILE_ATTRIBUTE_DIRECTORY
      ((check_ret[2] >> 4) & 0x1) &&
      # FILE_ATTRIBUTE_REPARSE_POINT
      ((check_ret[2] >> 10) && 0x1)
    )
      return TRUE;

    check_path = ereg_replace(
      pattern:'^(.*)\\\\([^\\\\]*)?$',
      replace:"\1",
      string:check_path
    );
  }
  return FALSE;
}

kb_base = "SMB/Dropbox";


# Look for it in the Uninstall hive.
installstring = "";
list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (!isnull(list))
{
  foreach name (keys(list))
  {
    prod = list[name];
    if (prod && "Dropbox" >< prod)
    {
      installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
      installstring = str_replace(find:"/", replace:"\", string:installstring);
      break;
    }
  }
}


# Connect to the appropriate share
name      = kb_smb_name();
port      = kb_smb_transport();
#if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");
login     = kb_smb_login();
pass      = kb_smb_password();
domain    = kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(1, "Failed to open a socket on port "+port+".");

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

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

# Find where it's installed.
paths = make_array();
pdir = "";

if (installstring)
{
  key_h = RegOpenKey(handle:hklm, key:installstring, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"InstallLocation");
    if (!isnull(item))
    {
      path = item[1];
      lcpath = tolower(path);
      if (!paths[lcpath]) paths[lcpath] = path;
    }
    RegCloseKey(handle:key_h);
  }
}

user_values = get_hku_key_values(key:"\SOFTWARE\Dropbox", reg_init:FALSE, resolve_sid:FALSE);
user_dropbox_dirs = [];
foreach(user_value in user_values)
{
  path = user_value['installpath'];
  if(empty_or_null(path)) continue;
  
  lcpath = tolower(path);
  if (!paths[lcpath]) paths[lcpath] = path;
}

RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if (max_index(keys(paths)) == 0)
{
  NetUseDel();
  exit(0, "Dropbox does not appear to be installed.");
}


# Look for installs and prepare report.
install_count = 0;

spad_log(message:'Paths found: ' + obj_rep(paths));

# Add some typical default paths, which may not bear fruit if not present
paths["c:\program files\dropbox\client"] = 'C:\\Program Files\\Dropbox\\Client';
paths["c:\program files (x86)\dropbox\client"] = 'C:\\Program Files (x86)\\Dropbox\\Client';

spad_log(message:'Paths to check: ' + obj_rep(paths));

foreach path (paths)
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Dropbox.exe", string:path);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc == 1)
  {
    # Look for, and skip, Windows Reparse Points
    # that would cause one install to be reported
    # twice.
    strip_path = dirpat - "\*";
    if (reparse_points_exist_in_path(check_path:strip_path))
    {
      spad_log(message:'Reparse point found in path ' + strip_path);
      continue;
    }

    fh = CreateFile(
      file:exe,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      ver = GetFileVersion(handle:fh);
      CloseFile(handle:fh);

      if (!isnull(ver))
      {
        version = join(ver, sep:".");

        set_kb_item(name:kb_base+"/"+version, value:path);

        register_install(
          vendor:"Dropbox",
          product:"Dropbox",
          app_name:app,
          path:path,
          version:version,
          cpe:"cpe:/a:dropbox:dropbox");

        install_count += 1;
      }
      else
        spad_log(message:'Unable to determine version.');
    }
    else
      spad_log(message:'Unable to locate file ' + exe + ' on drive ' + share);
  }
}

if (!install_count)
{

  # We have evidence of a Dropbox installation
  #
  # Iterate over list again, this time
  #  adding installations with reparse points in
  #  the path -- but only if they were not already found
  foreach path (paths)
  {
    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
    exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Dropbox.exe", string:path);
    NetUseDel(close:FALSE);

    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc == 1)
    {
      strip_path = dirpat - "\*";

      fh = CreateFile(
        file:exe,
        desired_access:GENERIC_READ,
        file_attributes:FILE_ATTRIBUTE_NORMAL,
        share_mode:FILE_SHARE_READ,
        create_disposition:OPEN_EXISTING
      );
      if (!isnull(fh))
      {
        ver = GetFileVersion(handle:fh);
        CloseFile(handle:fh);

        if (!isnull(ver))
        {
          version = join(ver, sep:".");

          # Reported paths containing Reparse points may
          #  indicate multiple paths for the same installation
          if (get_kb_item(kb_base+"/"+version))
          {
            spad_log(message:'Installation with version ' + version + ' already detected.');
            continue;
          }

          set_kb_item(name:kb_base+"/"+version, value:path);

          register_install(
            vendor:"Dropbox",
            product:"Dropbox",
            app_name:app,
            path:path,
            version:version,
            cpe:"cpe:/a:dropbox:dropbox");

          install_count += 1;
        }
	else
          spad_log(message:'Unable to determine version.');
      }
      else
        spad_log(message:'Unable to locate file ' + exe + ' on drive ' + share);
    }
  }
}

if (install_count)
{
  set_kb_item(name:kb_base+"/Installed", value:TRUE);

  report_installs(app_name:app, port:port);
  exit(0);
}
else exit(0, "No Dropbox installs were found although traces of it were found in the registry."+extra);
