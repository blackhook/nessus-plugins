#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34112);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/06");

  script_xref(name:"IAVT", value:"0001-T-0746");

  script_name(english:"Wireshark / Ethereal Detection (Windows)");
  script_summary(english:"Determines if Wireshark/Ethereal is installed");

 script_set_attribute(attribute:"synopsis", value:"A network protocol analyzer is installed on the remote host.");
 script_set_attribute(attribute:"description", value:
"Wireshark (formerly known as Ethereal) is installed on the remote
Windows host.

Wireshark is a popular open source network protocol analyzer (sniffer)
typically used for network troubleshooting and protocol analysis.");
 script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/about.html");
 script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/news/20060607.html" );
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/09");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
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
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");
include("install_func.inc");
include("smb_hotfixes.inc");
include("smb_reg_query.inc");
include("smb_hotfixes_fcheck.inc");
include("spad_log_func.inc");

# Get the install path

name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}

exes = make_array();
paths = make_array();
foreach sniffer (make_list("Wireshark", "Ethereal"))
{
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\" + tolower(sniffer) + '.exe';
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(item)) exes[sniffer] = item[1];

    item = RegQueryValue(handle:key_h, item:"Path");
    if (!isnull(item)) paths[sniffer] = item[1];

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

var vendor = 'Wireshark';
info = "";
foreach sniffer (keys(paths))
{
  exe = exes[sniffer];
  path = paths[sniffer];

  share = ereg_replace(pattern:"^([A-Za-z]):.+", replace:"\1$", string:exe);
  exe2 =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:exe);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1);
  }

  fh = CreateFile(file:exe2,
	desired_access:GENERIC_READ,
	file_attributes:FILE_ATTRIBUTE_NORMAL,
	share_mode:FILE_SHARE_READ,
	create_disposition:OPEN_EXISTING);

  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    if (!isnull(ver))
    {
      version = ver[0] +  "." +  ver[1] +  "." +  ver[2];
      set_kb_item(name:"SMB/Wireshark/"+version, value:path);

      register_install(
        vendor:vendor,
        product:"Wireshark",
        app_name:sniffer,
        path:path,
        version:version,
        extra_no_report:make_array('os', 'win'),
        cpe:"cpe:/a:wireshark:wireshark");

      info += '  Application : ' + sniffer + '\n' +
              '  Path        : ' + path + '\n' +
              '  Version     : ' + version + '\n' +
              '\n';

      CloseFile(handle:fh);
    }
  }
}
NetUseDel();

if (empty_or_null(info))
{
  spad_log(message:"Wireshark standard installation not detected.");
  installed = FALSE;

  list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
  if (!isnull(list))
  {
    foreach name (keys(list))
    {
      prod = list[name];
      if (!isnull(prod) && "Wireshark" >< prod)
      {
        spad_log(message:"Wireshark uninstall registry key found: " + prod);
        installed = TRUE;
        break;             # multiple may be present
      }
    }
  }

  if (!installed)
  {
    registry_init();
    hku = registry_hive_connect(hive:HKEY_USERS, exit_on_fail:TRUE);
    base_key = ".DEFAULT\\Software";
    subkeys = get_registry_subkeys(handle:hku, key:base_key);
    close_registry();
    if (!empty_or_null(subkeys))
    {
      foreach key (keys(subkeys))
      {
        if ("Wireshark" >< subkeys[key])
        {
          spad_log(message:"Wireshark installed via SCCM as per registry path HKEY_USERS\\.DEFAULT\\Software\\Wireshark");
          installed = TRUE;
          break;
        }
      }
    }
  }

  if (installed)
  {
    sysroot = hotfix_get_programfilesdir();
    sysrootx86 = hotfix_get_programfilesdirx86();

    # In case there are more reported, allow this to increase
    default_paths = [
      { 'path':'\\Wireshark\\Wireshark.exe', 'x86':0 }
      ];

    foreach path (keys(default_paths))
    {
      if (default_paths[path]['x86'])
        default_path = hotfix_append_path(path:sysrootx86, value:default_paths[path]['path']);
      else
        default_path = hotfix_append_path(path:sysroot, value:default_paths[path]['path']);

      spad_log(message:'Checking default path ' + default_path);
      full_ver = hotfix_get_fversion(path:default_path);
      if (full_ver.error == HCF_OK)
      {
        version = full_ver['value'][0] +  "." +  full_ver['value'][1] +  "." +  full_ver['value'][2];
        default_path = default_path - "\Wireshark.exe";
        set_kb_item(name:"SMB/Wireshark/"+version, value:default_path);

        register_install(
          vendor:vendor,
          product:"Wireshark",
          app_name:"Wireshark",
          path:default_path,
          version:version,
          extra_no_report:make_array('os', 'win'),
          cpe:"cpe:/a:wireshark:wireshark");

        info += '  Application : Wireshark\n' +
                '  Path        : ' + default_path + '\n' +
                '  Version     : ' + version + '\n' +
                '\n';
      }
      hotfix_check_fversion_end();
    }
  }
}

if (info)
{
  set_kb_item(name:"SMB/Wireshark/Installed", value:TRUE);
  security_report_v4(port:port, extra:'\n' + info, severity:SECURITY_NOTE);
}
