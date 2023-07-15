#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(51351);
  script_version("1.39");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/18");

  script_xref(name:"IAVT", value:"0001-T-0655");

  script_name(english:"Microsoft .NET Framework Detection");

  script_set_attribute(attribute:"synopsis", value:
"A software framework is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Microsoft .NET Framework, a software framework for Microsoft Windows
operating systems, is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://www.microsoft.com/net");
  # https://support.microsoft.com/en-us/help/318785/how-to-determine-which-versions-and-service-pack-levels-of-the-microso
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15ae6806");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
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

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('install_func.inc');

function retrieve_net_dirs(root_dir)
{
  local_var results, raw_results, net_share, file, version, dir, sys;
  
  # 1. list all dirs starting with "v", e.g., v3.0
  # 2. extract version and map it to the dir 
  sys = hotfix_get_systemdrive(as_dir:TRUE);
  results = make_array();
  net_share = hotfix_path2share(path:root_dir);
  # remove drive from the path, e.g., C:. we need this for list_dir()
  root_dir = ereg_replace(string:root_dir, pattern:"^[A-Za-z]:(.*)\\$", replace:"\1");
  raw_results = list_dir(basedir: root_dir, level: 0, file_pat: "v\d+(\.\d+)+", max_recurse:0, share:net_share);
  if (!empty_or_null(raw_results))
  {
    foreach file (raw_results)
    {
      version = pregmatch(string:file, pattern:"v(\d(\.\d+)+)$");
      if (!isnull(version))
      {
        version = version[1];
        dir = sys - "\" + file;
        results[version] = dir;
      }
    }
  }
  return results;
}

# declaring all vars
var app, hklm, key, keys, key_h, value, sp, path, version, full_version, v;
var unknown_index, install_count, install_types, extra, v1_installed, port;
var dotnet_release, type, key2, key2_h, kb_entry, net_fw_install_root;
var net_dirs, subkey, subkeys;

app = "Microsoft .NET Framework";

get_kb_item_or_exit("SMB/Registry/Enumerated");

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

key = "SOFTWARE\Microsoft\.NETFramework";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallRoot");
  if(!isnull(value))
  {
    # e.g., SMB/net_framework/InstallRoot 
    kb_entry = "SMB/net_framework/InstallRoot";
    net_fw_install_root = value[1];
    set_kb_item(name:kb_entry,value:net_fw_install_root);
  }
  RegCloseKey(handle:key_h);
}

if (empty_or_null(net_fw_install_root))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0,"Microsoft .NET Framework is not installed on the remote host.");
}
else
{
  RegCloseKey(handle: hklm);
  close_registry(close: FALSE);
  # Retrieve specific NET dirs
  net_dirs = retrieve_net_dirs(root_dir:net_fw_install_root);
  hotfix_check_fversion_end();
  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
}

# Find where it's installed.
sp =  '';
path = '';
version = '';
full_version = '';
unknown_index = 0;
install_count = 0;

install_types = make_list("Full","Client","");

key = "SOFTWARE\Microsoft\NET Framework Setup\NDP";
subkeys = get_registry_subkeys(handle:hklm, key:key);

foreach subkey (subkeys)
{
  if (strlen(subkey) && subkey =~ "^[v0-9.]+$")
  {
    # Ignore the registry entry for v4.0 as this will not contain
    # Full or Client entries when .NET 4.0 is installed and
    # with 4.5.x installed, the v4.0 entry will have Client and flag
    # so we ignore this below.  Note that 4.5 replaces the 4.0 assemblies
    # https://msdn.microsoft.com/en-us/library/5a4x27ek%28v=vs.110%29.aspx
    if (subkey =~ "^v4\.0") continue;
    foreach type (install_types)
    {
      key2 = key + "\" + subkey + '\\' + type;
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if(!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"Install");
        if(!isnull(value) && value[1])
        {
          extra = make_array();
          version = preg_replace(pattern:"^v([0-9.]+)$",string:subkey,replace:"\1");
          if (version =~ "^4")
          {
            # http://msdn.microsoft.com/en-us/library/hh925568(v=vs.110).aspx
            dotnet_release = RegQueryValue(handle:key2_h, item:"Release");
            if(!isnull(dotnet_release) && dotnet_release[1])
            {
              extra['Release'] = dotnet_release[1];
              if (dotnet_release[1] == '378389')
                version = '4.5';
              if (dotnet_release[1]=='378675' || dotnet_release[1]=='378758')
                version = '4.5.1';
              # 380013 is from https://support.microsoft.com/en-us/kb/3099856
              # 380035 is from https://support.microsoft.com/en-us/help/3146718
              if (dotnet_release[1] == '379893' || dotnet_release[1]=='379962' || dotnet_release[1]=='380035' || dotnet_release[1]=='380013' || dotnet_release[1]=='380026')
                version = '4.5.2';
              if (dotnet_release[1] == '381029' || dotnet_release[1] == '393273')
                version = '4.6 Preview';
              # 393295 is Windows 10, 393297 is all other versions.
              if (dotnet_release[1] == '393295' || dotnet_release[1] == '393297')
                version = '4.6';
              # 394254 is Windows 10, 394271 is all other versions.
              # 394294 is from https://support.microsoft.com/en-us/kb/3146716
              if (dotnet_release[1] == '394254' || dotnet_release[1] == '394271' || dotnet_release[1] == '394294' || dotnet_release[1] == '394297')
                version = '4.6.1';
              # 394747 is Windows 10, 394748 is all other versions. Pre-view numbers.
              if (dotnet_release[1] == '394747' || dotnet_release[1] == '394748' ||
              # 394802 is Windows 10, 394806 is all other versions. Anniversary Update.
                  dotnet_release[1] == '394802' || dotnet_release[1] == '394806')
                version = '4.6.2';
              if (dotnet_release[1] == '460798' || dotnet_release[1] == '460805')
                version = '4.7';
              # 461308 is Windows 10 Fall Creators Update, 461310 is all other versions.
              if (dotnet_release[1] == '461308' || dotnet_release[1] == '461310')
                version = '4.7.1';
              # 461808 is Windows 10 Fall Creators Update, 461814 is all other versions.
              if (dotnet_release[1] == '461808' || dotnet_release[1] == '461814')
                version = '4.7.2';
              # 528449 is included with Windows 11 & Server 2022, 528040 is Windows 10 May 2019 Update, 528209 is Windows 10 May 2020, and 528049 is all other versions.
              if (dotnet_release[1] == '528449' || dotnet_release[1] == '528049' || dotnet_release[1] == '528040' || dotnet_release[1] == '528372' || dotnet_release[1] == '528209')
                version = '4.8';
              # 533320 for Windows 11 22H2, release 533325 for all other Windows OS versions.
              if (dotnet_release[1] == '533325' || dotnet_release[1] == '533320')
                version = '4.8.1';  

            }
          }

          if(type)
          {
            extra['Install Type'] = type;
          }

          value =  RegQueryValue(handle:key2_h, item:"Version");
          if(!isnull(value) && value[1])
          {
            full_version = value[1] ;
            extra['Full Version'] = full_version;
          }

          # Service pack
          value =  RegQueryValue(handle:key2_h, item:"SP");
          if(!isnull(value))
          {
            sp = value[1];
            extra['SP'] = sp;
          }

          value =  RegQueryValue(handle:key2_h, item:"InstallPath");
          if(!isnull(value) && value[1])
          {
            path = value[1];
          }
          else if (!empty_or_null(version))
          {
            # setting root path for NET Framework
            path = net_dirs[version];

            # if we still don't know the path, set it to unknown
            if (empty_or_null(path) || path == "multiple")
              path = "Unknown " + unknown_index++;
          }

          register_install(
            app_name:app,
            vendor : 'Microsoft',
            product : '.NET Framework',
            path:path,
            version:version,
            extra:extra,
            cpe:"cpe:/a:microsoft:.net_framework");

          install_count += 1;
        }
        RegCloseKey(handle:key2_h);
      }
      version = full_version = sp = path = '';
    }
  } 
}

# Is there evidence of v1.0 installed??

v1_installed = 0;
key = "Software\Microsoft\.NETFramework\Policy\v1.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value =  RegQueryValue(handle:key_h, item:"3705");
  if(!isnull(value))
    v1_installed = 1;

  RegCloseKey(handle:key_h);
}

# Now get the Full version/SP

if(v1_installed)
{
  keys = make_list("Software\Microsoft\Active Setup\Installed Components\{78705f0d-e8db-4b2d-8193-982bdda15ecd}",
                 "Software\Microsoft\Active Setup\Installed Components\{FDC11A6F-17D1-48f9-9EA3-9051954BAA24}");

  foreach key (keys)
  {
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      version =  "1.0.3705";

      value = RegQueryValue(handle:key_h, item:"Version");
      if (!isnull(value))
      {
        extra = make_array();
        v = split(value[1],sep:",",keep:FALSE);

        full_version =  join(v, sep:".");

        extra['Full Version'] = full_version;

        # extract the SP , for e.g. 1.0.3705.1
        # 1 is the SP.
        matches = pregmatch(pattern:"^[0-9]+\.[0-9]+\.[0-9]+\.([0-9]+)$",string:full_version);
        if(!isnull(matches))
        {
          sp = matches[1];
          extra['SP'] = sp;
        }
        path = net_dirs[version];
        if (!empty_or_null(path))
          path = "Unknown " + unknown_index++;;

        register_install(
          app_name:app,
          vendor : 'Microsoft',
          product : '.NET Framework',
          path:path,
          version:version,
          extra:extra,
          cpe:"cpe:/a:microsoft:.net_framework");

        install_count += 1;
      }
      RegCloseKey(handle:key_h);
    }
  }
}
RegCloseKey(handle:hklm);
NetUseDel();

if (install_count)
{
  port = kb_smb_transport();
  report_installs(app_name:app, port:port);
  exit(0);
}
else exit(0, "Microsoft .NET Framework is not installed on the remote host.");
