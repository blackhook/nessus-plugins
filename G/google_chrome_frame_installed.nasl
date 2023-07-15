#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42894);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_name(english:"Google Chrome Frame Detection (Windows)");

  script_set_attribute(attribute:"synopsis", value:
"A browser plugin is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Google Chrome Frame, an open source plug-in that enables support for
HTML5 and other open web technologies in Internet Explorer (IE) is
installed on the remote Windows host.

According to Microsoft, use of this plugin with IE can potentially
make IE less secure, and hence its use is not recommended.");
  # https://www.chromium.org/developers/how-tos/chrome-frame-getting-started
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f336c8d");
  # https://arstechnica.com/information-technology/2009/09/microsoft-google-chrome-frame-makes-ie-less-secure/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c6c95d6");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

app = "Google Chrome Frame";

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
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, 'IPC$');
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

key = "SOFTWARE\Classes\Applications\ChromeHTML\shell\open\command";
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

key = "SOFTWARE\Clients\StartMenuInternet\Google Chrome Frame\shell\open\command";
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

# Newer versions ( > 4.0.245.1) store info here...
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome Frame";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
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

RegCloseKey(handle:hklm);

# If the "Perform thorough tests" setting is enabled, include local user directories too.
if (thorough_tests)
{
  # Find out where user directories are stored.

  hku = registry_hive_connect(hive:HKEY_USERS, exit_on_fail:TRUE);
  subkeys = get_registry_subkeys(handle:hku, key:'');
  foreach key (subkeys)
  {
    # verify Chrome Frame is installed and available for user
    key_part = '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Google Chrome Frame\\InstallLocation';
    path = get_registry_value(handle:hku, item:key + key_part);
    if(!isnull(path)) # add a path to check
    {
      lcpath = tolower(path);
      if (!paths[lcpath]) paths[lcpath] = path;
    }
  }
}

RegCloseKey(handle:hku);
NetUseDel(close:FALSE);

if(max_index(keys(paths)) == 0)
  audit(AUDIT_NOT_INST, app);

# Determine version numbers of any actual Chrome Frame installs.
vers = make_array();

foreach lcpath (keys(paths))
{
  path = paths[lcpath];
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  dirpat = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\*", string:path);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc == 1)
  {
    retx = FindFirstFile(pattern:dirpat);
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
	   # nb : Only one version/user of Chrome Frame can be installed at a
           #      time. While upgrading to newer versions, older versions are
           #      replaced with newer versions.

            version = ver[0] + "." + ver[1] + "." + ver[2] + "." + ver[3];
            vers[version] = path;
          }
          CloseFile(handle:fh);
        }
      }
      retx = FindNextFile(handle:retx);
    }
  }
}

NetUseDel();

# If any installs were found, mark it as installed in the KB and issue a report.
if (max_index(keys(vers)))
{
  set_kb_item(name:"SMB/Google_Chrome_Frame/Installed", value:TRUE);

  info = "";
  foreach version (sort(keys(vers)))
  {
    path = vers[version];
    if(!isnull(path))
    {
      set_kb_item(name:"SMB/Google_Chrome_Frame/"+version, value:path);

      register_install(
        app_name:app,
        vendor : 'Google',
        product : 'Chrome Frame',
        path:path,
        version:version,
        cpe:"cpe:/a:google:chrome");
    }
  }

  if (!thorough_tests)
  {
    # nb: report already has an extra blank line at the end.
    info =
      "Note that Nessus only looked in the registry for evidence of Google" + '\n' +
      "Chrome Frame. If there are multiple users on this host, you may wish to" + '\n' +
      "enable the 'Perform thorough tests' setting and re-scan. This will" + '\n' +
      "cause Nessus to scan each local user's directory for installs." + '\n';
  }

  report_installs(app_name:app, port:port, extra:info);
  exit(0);
}
else audit(AUDIT_UNINST, app);
