#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34196);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");
  script_xref(name:"IAVT", value:"0001-T-0511");

  script_name(english:"Google Chrome Detection (Windows)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser.");
  script_set_attribute(attribute:"description", value:
"Google Chrome, a web browser from Google, is installed on the remote
Windows host.");
  script_set_attribute(attribute:"see_also", value:"https://www.google.com/chrome/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("smb_func.inc");
include("misc_func.inc");
include("install_func.inc");

app = "Google Chrome";
fa_app_name = "chrome";

# Walk up the path and check if each directory
# in the path is a reparse point.
function reparse_points_exist_in_path(check_path)
{
  local_var check_ret;

  while (check_path != "\" && strlen(check_path) > 0)
  {
    check_ret = FindFirstFile(pattern:check_path);

    # Look for reparse point directories
    # in file attributes.
    if (!isnull(check_ret[2]) &&
      # FILE_ATTRIBUTE_DIRECTORY
      ((check_ret[2] >> 4) & 0x1) &&
      # FILE_ATTRIBUTE_REPARSE_POINT
      ((check_ret[2] >> 10) & 0x1)
    )
      return TRUE;

    check_path = ereg_replace(
      pattern:"^(.*)\\([^\\]*)?$",
      replace:"\1",
      string:check_path
    );
  }
  return FALSE;
}


get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) audit(AUDIT_SOCK_FAIL, port);

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}


# Determine possible paths where it might be installed.
paths = make_array();
keys = make_list(
  "SOFTWARE\Classes\Applications\chrome.exe\shell\open\command",
  "SOFTWARE\Classes\ChromeHTML\shell\open\command",
  "SOFTWARE\Clients\StartMenuInternet\chrome.exe\shell\open\command",
  "SOFTWARE\Clients\StartMenuInternet\Google Chrome\shell\open\command"
);

var path = NULL;

foreach key (keys)
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(item))
    {
      # nb: the exe itself appears in quotes.
      exe = ereg_replace(pattern:'^"([^"]+)".*', replace:"\1", string:item[1]);
      path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe.*$', replace:"\1", string:exe, icase:TRUE);
      lcpath = tolower(path);
      if (!paths[lcpath]) paths[lcpath] = path;
    }
    RegCloseKey(handle:key_h);
  }
}

# If the "Perform thorough tests" setting is enabled, include local user directories too.
pdir = "";

if (thorough_tests)
{
  # Find out where user directories are stored.

  key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"ProfilesDirectory");
    if (!isnull(item)) pdir = item[1];

    RegCloseKey(handle:key_h);
  }

  if (pdir && stridx(tolower(pdir), "%systemdrive%") == 0)
  {
    key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      item = RegQueryValue(handle:key_h, item:"SystemRoot");
      if (!isnull(item))
      {
        winroot = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1:", string:item[1]);
        pdir = winroot + substr(pdir, strlen("%systemdrive%"));
      }

      RegCloseKey(handle:key_h);
    }
  }
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if (pdir)
{
  # Get OS ver
  windows_version = get_kb_item("SMB/WindowsVersion");

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:pdir);
  dirpat = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\*", string:pdir);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc == 1)
  {
    retx = FindFirstFile(pattern:dirpat);
    var user;
    while (!isnull(retx[1]))
    {
      path = NULL;
      user = retx[1];
      if (user != "." && user != "..")
      {
        # 2k / 2k3 / XP
        if (windows_version < 6 )
          path = pdir + "\" + user + "\Local Settings\Application Data\Google\Chrome\Application";
        # Vista / Win 7 / 2k8
        else
          path = pdir + "\" + user + "\AppData\Local\Google\Chrome\Application";

        if (!isnull(path))
        {
          lcpath = tolower(path);
          if (!paths[lcpath]) paths[lcpath] = path;
        }
      }
      retx = FindNextFile(handle:retx);
    }
  }
}

# Determine version numbers of any actual Chrome installs.
vers = make_array();


##
#  Check both 'Program Files (x86)' and 'Program Files'
#  Use uppercase path keys to ensure uniqueness
##
var altpath, up_altpath, altpaths, path_ds, up_path;
foreach path (paths)
{
  up_path = toupper(path);
  path_ds[up_path].display_path = path;  
  if ("Program Files (x86)" >< path)
  {
    altpath = path - " (x86)";
    up_altpath = toupper(altpath);
    altpaths[up_altpath].display_path = altpath;
  }
  else if ("Program Files" >< path)
  {
    altpath = ereg_replace(string:path, pattern:"Program Files", replace:"Program Files (x86)");
    up_altpath = toupper(altpath);
    altpaths[up_altpath].display_path = altpath;
  }
}
foreach altpath (keys(altpaths))
  path_ds[altpath].display_path = altpaths[altpath].display_path;


spad_log(message:'path datastructure: ' + obj_rep(path_ds));

##
#  Check paths
##
foreach var path_key (keys(path_ds))
{
  path = path_ds[path_key].display_path;
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  dirpat = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\*", string:path);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc == 1)
  {

    # Look for, and skip, Windows Reparse Points
    # that would cause one install to be reported
    # twice.
    strip_path = dirpat - "\*";
    if (reparse_points_exist_in_path(check_path:strip_path))
      continue;

    max_version = "";
    retx = FindFirstFile(pattern:dirpat);

    var dir, fh, dll, ver, i, max;
    while (!isnull(retx[1]))
    {
      dir = retx[1];
      if (dir =~ "^[0-9]+[0-9.]+$")
      {
        dll = substr(dirpat, 0, strlen(dirpat)-2-1) + "\" + dir + "\chrome.dll";
        fh = CreateFile(
          file:dll,
          desired_access:GENERIC_READ,
          file_attributes:FILE_ATTRIBUTE_NORMAL,
          share_mode:FILE_SHARE_READ,
          create_disposition:OPEN_EXISTING
        );
        if (!isnull(fh))
        {
          ver = GetFileVersion(handle:fh);
          if (!isnull(ver))
          {
            version = ver[0] +  "." +  ver[1] +  "." +  ver[2] +  "." +  ver[3];
            # nb: upgrades don't remove old versions so we look for the highest.
            if (!max_version) max_version = version;
            else
            {
              max = split(max_version, sep:'.', keep:FALSE);
              for (i=0; i<4; i++)
                max[i] = int(max[i]);

              if (
                ver[0] > max[0] ||
                (ver[0] == max[0] && ver[1] > max[1]) ||
                (ver[0] == max[0] && ver[1] == max[1] && ver[2] > max[2]) ||
                (ver[0] == max[0] && ver[1] == max[1] && ver[2] == max[2] && ver[3] > max[3])
              ) max_version = version;
            }
          }
          CloseFile(handle:fh);
        }
      }
      retx = FindNextFile(handle:retx);
    }

    if (max_version)
    {
      if (vers[max_version]) vers[max_version] += ";" + path;
      else vers[max_version] = path;
    }
  }
}
NetUseDel();


# If any installs were found, mark it as installed in the KB and issue a report.
if (max_index(keys(vers)))
{
  set_kb_item(name:"SMB/Google_Chrome/Installed", value:TRUE);

  info = "";
  foreach version (sort(keys(vers)))
  {
    foreach path (sort(split(vers[version], sep:";", keep:FALSE)))
    {
      set_kb_item(name:"SMB/Google_Chrome/"+version+"/"+path, value:path);

      register_install(
        app_name:app,
        vendor : 'Google',
        product : 'Chrome',
        path:path,
        version:version,
        cpe:"cpe:/a:google:chrome",
        fa_app_name: fa_app_name);
    }
  }

  if (!thorough_tests)
  {
    # nb: report already has an extra blank line at the end.
    info +=
      'Note that Nessus only looked in the registry for evidence of Google\n' +
      'Chrome. If there are multiple users on this host, you may wish to\n' +
      "enable the 'Perform thorough tests' setting and re-scan. This will" + '\n' +
      "cause Nessus to scan each local user's directory for installs." + '\n';
  }

  report_installs(app_name:app, port:port, extra:info);
}
else
{
  audit(AUDIT_NOT_INST, app);
}