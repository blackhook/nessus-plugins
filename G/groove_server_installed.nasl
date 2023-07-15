#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49977);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_name(english:"Microsoft Groove Server Installed");
  script_summary(english:"Checks if Groove Server is installed");

  script_set_attribute(attribute:"synopsis", value:
"A management server for document collaboration is installed on the
remote Windows host.");
  script_set_attribute(attribute:"description", value:
"Microsoft Groove Server is installed on the remote host. This
application is used to centrally manage deployments of Microsoft
Office Groove and Microsoft SharePoint Workspace.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d64cfd46");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:groove_server");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

app = "Microsoft Groove Server";

name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

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

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

paths = make_list();
key = "SOFTWARE\Microsoft\Office Server";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && preg(pattern:'^[0-9.]+$', string:subkey))
    {
      key2 = key + "\" + subkey + "\Groove";
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        item2 = RegQueryValue(handle:key2_h, item:"EMSInstallDir");
        if (!isnull(item2)) paths = make_list(paths, item2[1]);
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (max_index(paths) == 0)
{
  NetUseDel();
  exit(0, "No evidence of Groove Server was found in the registry.");
}


install_count = 0;
foreach path (paths)
{
  share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
  file =  ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\GROOVEMS.DLL", string:path);

  NetUseDel(close:FALSE);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to the '"+share+"' share.");
  }

  fh = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  # If the file can't be opened, it's like because it's been uninstalled.
  if (fh)
  {
    set_kb_item(name:'SMB/groove_server/path', value:path);

    register_install(
      app_name:app,
      vendor : 'Microsoft',
      product : 'Groove Server',
      path:path,
      cpe: "cpe:/a:microsoft:groove_server");

    install_count += 1;

    CloseFile(handle:fh);
  }
}

NetUseDel();

if (!install_count) exit(0, 'No Groove Server installs were detected.');

report_installs(app_name:app, port:port);

