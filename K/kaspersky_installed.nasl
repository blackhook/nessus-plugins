#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20284);
  script_version("1.1840");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_name(english:"Kaspersky Endpoint Security Detection and Status");
  script_summary(english:"Checks for Kaspersky Endpoint Security.");

  script_set_attribute(attribute:"synopsis", value:
"An endpoint security application is installed on the remote host, but it is
not working properly.");
  script_set_attribute(attribute:"description", value:
"Kaspersky Endpoint Security, a commercial endpoint security software package for
Windows, is installed on the remote host. However, there is a problem
with the installation; either its services are not running or its
engine and/or virus definitions are out of date.");
  script_set_attribute(attribute:"see_also", value:"https://www.kaspersky.com/");
  script_set_attribute(attribute:"solution", value:
"Make sure that updates are working and the associated services are
running.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on the antivirus not working properly.");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kaspersky:kaspersky_anti-virus");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"asset_categories", value:"security_control");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/transport", "SMB/Services/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("antivirus.inc");
include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");
include("install_func.inc");
include("debug.inc");
include("security_controls.inc");
include("spad_log_func.inc");

cpe = "cpe:/a:kaspersky:kaspersky_anti-virus";

# Connect to the remote registry.
get_kb_item_or_exit("SMB/registry_full_access");
get_kb_item_or_exit("SMB/Services/Enumerated");

name    = kb_smb_name();
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();
port    = kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, 'IPC$');
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# Check if the software is installed.
base_dir = NULL;
name = NULL;
path = NULL;
prodinfo = NULL;
sig_path = NULL;
upd_cfg = NULL;
ver = NULL;
autoupdate_status = NULL;

# The ones with update_subkeys=NULL have a different registry layout than regular KAV,
# so we can't extrapolate where the autoupdate status resides,
# but they are super old (10-15 years), so we probably won't see them anyway.
# - KAV 15
prod_subkeys = make_array();
update_subkeys = make_array();
name_subkeys = make_array();
path_subkeys = make_array();
ver_subkeys = make_array();
prod++;
prod_subkeys[prod] = "KasperskyLab\AVP15.0.0\environment";
update_subkeys[prod] = "KasperskyLab\AVP15.0.0\Data\ProductUpdate";
name_subkeys[prod] = "ProductName";
path_subkeys[prod] = "ProductRoot";
ver_subkeys[prod]  = "ProductVersion";
# - KAV 14
prod++;
prod_subkeys[prod] = "KasperskyLab\protected\AVP14.0.0\environment";
update_subkeys[prod] = "KasperskyLab\AVP14.0.0\Data\ProductUpdate";
name_subkeys[prod] = "ProductName";
path_subkeys[prod] = "ProductRoot";
ver_subkeys[prod]  = "ProductVersion";
# - KAV 7.0 (Internet Security / Anti-Virus / Anti-Virus for Windows Workstations / Anti-Virus for Windows Servers)
prod++;
prod_subkeys[prod] = "KasperskyLab\protected\AVP7\environment";
update_subkeys[prod] = "KasperskyLab\AVP7\Data\ProductUpdate";
name_subkeys[prod] = "ProductName";
path_subkeys[prod] = "ProductRoot";
ver_subkeys[prod]  = "ProductVersion";
# - KAV 6.0 (Internet Security / Anti-Virus / Anti-Virus for Windows Workstations / Anti-Virus for Windows Servers)
prod++;
prod_subkeys[prod] = "KasperskyLab\AVP6\Environment";
update_subkeys[prod] = "KasperskyLab\AVP6\Data\ProductUpdate";
name_subkeys[prod] = "ProductName";
path_subkeys[prod] = "ProductRoot";
ver_subkeys[prod]  = "ProductVersion";
# - KAV for Windows File Servers
prod++;
prod_subkeys[prod] = "Microsoft\Windows\CurrentVersion\Uninstall\{1A694303-9A42-43A8-A831-50F86C64EDF0}";
update_subkeys[prod] = NULL;
name_subkeys[prod] = "DisplayName";
path_subkeys[prod] = "InstallLocation";
ver_subkeys[prod]  = "DisplayVersion";
# - KAV for Workstations
prod++;
prod_subkeys[prod] = "KasperskyLab\InstalledProducts\Kaspersky Anti-Virus for Windows Workstations";
update_subkeys[prod] = NULL;
name_subkeys[prod] = "Name";
path_subkeys[prod] = "Folder";
ver_subkeys[prod]  = "Version";
# - KAV Personal / KAV Personal Pro
prod++;
prod_subkeys[prod] = "KasperskyLab\InstalledProducts\Kaspersky Anti-Virus Personal";
update_subkeys[prod] = NULL;
name_subkeys[prod] = "Name";
path_subkeys[prod] = "Folder";
ver_subkeys[prod]  = "Version";
# - KAV / KAV IS 2010
prod++;
prod_subkeys[prod] = "KasperskyLab\protected\AVP9\environment";
update_subkeys[prod] = "KasperskyLab\protected\AVP9\Data\ProductUpdate";
name_subkeys[prod] = "ProductName";
path_subkeys[prod] = "ProductRoot";
ver_subkeys[prod]  = "ProductVersion";

# More recent versions use a more predictable registry structure
# Look for evidence of the product in the subkeys and use that to
# determine the correct Registry hive to search
arch = get_kb_item("SMB/ARCH");
key_list = make_list("SOFTWARE\KasperskyLab\protected",
                     "SOFTWARE\KasperskyLab");

spad_log(message:'Arch: ' + arch);
if (arch == 'x64')
{
  key_list[max_index(key_list)] = "SOFTWARE\Wow6432Node\KasperskyLab\protected";
  key_list[max_index(key_list)] = "SOFTWARE\Wow6432Node\KasperskyLab";
}
foreach key (key_list)
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (isnull(key_h)) continue;

  info = RegQueryInfoKey(handle:key_h);
  if (isnull(info)) continue;

  for (i=0; i < info[1]; i++)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ '^(AVP|KES|PURE|KSVLA)([0-9]+|[0-9\\.]+)?((sp|SP)[0-9]+)?$')
    {
      key2 = key + '\\' + subkey + "\environment";
      # During the un-install process for some KASP products, artifact
      # keys can be left over, we need to verify key2 actually exists
      # before stopping our search, it maybe one of these artifacts
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if(isnull(key2_h))
      {
        key2 = NULL;
        RegCloseKey(handle:key2_h);
      }
      else
      {
        RegCloseKey(handle:key2_h);
        break;
      }
    }
  }
  if (!isnull(key2))
  {
    break;
  }
  else
  {
    RegCloseKey(handle:key_h);
  }
}


if (!key2)
{
  # check for Kaspersky Security for Windows Server v11 (differs from above)
  if (arch == 'x64')
  {
    key_list[max_index(key_list)] = "SOFTWARE\Wow6432Node\KasperskyLab\Components\34\Connectors\WSEE";
  }
  foreach key (key_list)
  {
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (isnull(key_h)) continue;

    info = RegQueryInfoKey(handle:key_h);
    if (isnull(info)) continue;

    for (i=0; i < info[1]; i++)
    {
      # determine 'version like' subkey which may change in the future
      # example: 10.1.0.0
      subkey = RegEnumKey(handle:key_h, index:i);
      spad_log(message:'Reading sub key: ' + obj_rep(subkey));

      if (!empty_or_null(subkey) && subkey =~ "[0-9.]")
      {
        key2 = key + '\\' + subkey;
        spad_log(message:'setting key to ' + key2);
        RegCloseKey(handle:key_h);
        break;
      }
      else
      {
        key2 = NULL;
      }
    }

    # We found we are looking for, no need to move on to the next item in key_list
    if (!isnull(key2))
    {
      break;
    }
    else
    {
      RegCloseKey(handle:key_h);
    }
  }
}

# If we found the correct registry hive, look for the product
# information
if (key2)
{
  spad_log(message:'Connecting to key2: ' + obj_rep(key2));
  key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
  if (!isnull(key2_h))
  {
    value = RegQueryValue(handle:key2_h, item:"ProductName");
    if (!isnull(value))
    {
      spad_log(message:'ProductName determined: ' + obj_rep(value));
      name = value[1];
      # get rid of version info in the name
      name = ereg_replace(string:name, pattern:" [0-9.]+", replace:"");
    }

    # If Product name is not found under "ProductName", try "ProdDisplayName"
    value = RegQueryValue(handle:key2_h, item:"ProdDisplayName");
    if (!isnull(value))
    {
      if (empty_or_null(name) && "Kaspersky Security for Windows Server" >< value[1])
      {
        spad_log(message:'ProdDisplayName determined: ' + obj_rep(value));
        name = value[1];
        # get rid of version info in the name
        name = ereg_replace(string:name, pattern:" [0-9.]+", replace:"");
      }
    }

    value = RegQueryValue(handle:key2_h, item:"ProductRoot");
    if (!isnull(value))
    {
      spad_log(message:'ProductRoot determined: ' + obj_rep(value));
      path = ereg_replace(string:value[1], pattern:"\$", replace:"");
    }

    spad_log(message:'First attempt to determine Product name and path Finished.\n'
                      + 'Name: ' + name + '\n'
                      + 'Path: ' + path);

    # if path is not found so far
    if (empty_or_null(path))
    {
      if (name == "Kaspersky Security for Windows Server")
      {
        value = RegQueryValue(handle:key2_h, item:"ConnectorPath");
        if (!isnull(value))
        {
          spad_log(message:'ConnectorPath determined: ' + obj_rep(value));
          path = ereg_replace(string:value[1], pattern:"\$", replace:"");
          path = ereg_replace(string:value[1], pattern:"\\ak_conn.dll", replace:"");
          spad_log(message:'Product path has not been determined in the first attempt. Set path to ' + obj_rep(path));
        }
      }
    }

    ###
    # Determine the Product version
    ###
    if (name == "Kaspersky Security for Windows Server")
    {
      value = RegQueryValue(handle:key2_h, item:"ProdVersion");
      if (!isnull(value))
      {
        ver = value[1];
        spad_log(message:'Version determined as ' + ver + ' using regkey ' + key2);
      }
    }

    if (isnull(ver))
    {
      value = RegQueryValue(handle:key2_h, item:"ProductDisplayVersion");
      if (!isnull(value))
      {
        spad_log(message:'ProductDisplayVersion determined: ' + obj_rep(value));

        # KES v11 seems to use ProductDisplayVersion instead of ProductVersion
        if (value[1] =~ "^11." && name == "Kaspersky Endpoint Security for Windows")
        {
          ver = value[1];
          spad_log(message:'KES v11 determined as ' + ver + ' using regkey ' + key2);
        }
      }
    }

    if (isnull(ver))
    {
      value = RegQueryValue(handle:key2_h, item:"ProductVersion");
      if (!isnull(value))
      {
        ver = value[1];
        spad_log(message:'Version determined as ' + ver + ' using regkey ' + key2);
      }
    }

    ###
    # Look for signature info
    ###
    value = RegQueryValue(handle:key2_h, item:"UpdateRoot");
    if (!isnull(value))
    {
      upd_cfg = value[1];
      upd_cfg = ereg_replace(pattern:"^.+/(.+\.xml)$", replace:"\1", string:upd_cfg);
    }

    data_dir = "%DataFolder%";
    i = 0;
    while (match = pregmatch(pattern:"%([a-zA-Z]+)%", string:data_dir))
    {
      value = NULL;
      if (!isnull(match))
      {
        s = match[1];
        value = RegQueryValue(handle:key2_h, item:s);
      }
      if (!isnull(value))
        data_dir = str_replace(find:"%"+s+"%", replace:value[1], string:data_dir);
      else break;

      # limit how many times we'll loop
      if (++i > 5) break;
    }

    if (!isnull(upd_cfg) && !isnull(data_dir)) upd_cfg = data_dir + '\\' + upd_cfg;
  
    base_dir = "%Base%";
    i = 0;
    while (match = pregmatch(pattern:"%([a-zA-Z]+)%", string:base_dir))
    {
      value= NULL;
      if (!isnull(match))
      {
        s = match[1];
        value = RegQueryValue(handle:key2_h, item:s);
      }
      if (!isnull(value))
        base_dir = str_replace(find:"%"+s+"%", replace:value[1], string:base_dir);
      else break;

      # limit how many times we'll loop
      if (++i > 5) break;
    }
    if (base_dir == "%Base%")
    {
      base_dir = "%Bases%";
      i = 0;

      while (match = pregmatch(pattern:"%([a-zA-Z]+)%", string:base_dir))
      {
        value = NULL;
        if (!isnull(match))
        {
          s = match[1];
          value = RegQueryValue(handle:key2_h, item:s);
        }
        if (!isnull(value))
          base_dir = str_replace(find:"%"+s+"%", replace:value[1], string:base_dir);
        else break;

        # limit how many times we'll loop
        if (++i > 5) break;
      }
    }
    RegCloseKey(handle:key2_h);
  }

  ###
  # Retrieving Auto Update status
  ###
  update_path = key2 - "\environment" + "\Data\ProductUpdate";
  spad_log(message:'Connecting to registry key ' + obj_rep(update_path));
  update_h = RegOpenKey(handle:hklm, key:update_path, mode:MAXIMUM_ALLOWED);
  if(isnull(update_h))
  {
    spad_log(message:'update_h null');
  }
  else
  {
    autoupdate_status = RegQueryValue(handle:update_h, item:"State");
    if(!isnull(autoupdate_status))
      autoupdate_status = autoupdate_status[1];
    else
      spad_log(message:'autoupdate_status is null');

    RegCloseKey(handle:update_h);
  }


  ###
  # Looking for Signature file
  ###
  if (isnull(data_dir) || isnull(base_dir))
  {
    # Some products point to it in the registry
    key3 = "SOFTWARE\KasperskyLab\Components\10a\LastSet";
    key3_h = RegOpenKey(handle:hklm, key:key3, mode:MAXIMUM_ALLOWED);
    if (!isnull(key3_h))
    {
      value = RegQueryValue(handle:key3_h, item:"Directory");
      if (!isnull(value))
      {
        sig_path = ereg_replace(string:value[1], pattern:"\$", replace:"");
        spad_log(message:'Signature path: ' + obj_rep(sig_path));
      }
    }
    RegCloseKey(handle:key3_h);

    # Some products point to it from SS_PRODINFO.xml
    key2 = "SOFTWARE\KasperskyLab\Components\34";
    key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
    if (!isnull(key2_h))
    {
      value = RegQueryValue(handle:key2_h, item:"SS_PRODINFO");
      if (!isnull(value))
      {
        prodinfo = ereg_replace(string:value[1], pattern:"\$", replace:"");
        spad_log(message:'Product Info: ' + obj_rep(prodinfo));
      }
    }
    RegCloseKey(handle:key2_h);
  }
  RegCloseKey(handle:key2_h);
}

# If we couldn't find the product info, it is probably an older version
# Use the pre-defined arrays to try to find product information
if (isnull(name) || isnull(path) || isnull(ver))
{
  spad_log(message:'Looking for product using product subkeys');

  foreach prod (keys(prod_subkeys))
  {
    key = "SOFTWARE\" + prod_subkeys[prod];
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

    if (!isnull(key_h)) {

      if(!isnull(update_subkeys))
      {
        update_path = "SOFTWARE\" + update_subkeys[prod];
        update_h = RegOpenKey(handle:hklm, key:update_path, mode:MAXIMUM_ALLOWED);
        autoupdate_status = RegQueryValue(handle:update_h, item:"State");
        if(!isnull(autoupdate_status)) autoupdate_status = autoupdate_status[1];
        RegCloseKey(handle:update_h);
      }

      value = RegQueryValue(handle:key_h, item:name_subkeys[prod]);
      if (!isnull(value))
      {
        spad_log(message:'ProductName determined: ' + obj_rep(value));
        name = value[1];
        # get rid of version info in the name.
        name = ereg_replace(string:name, pattern:" [0-9.]+", replace:"");
      }

      value = RegQueryValue(handle:key_h, item:path_subkeys[prod]);
      if (!isnull(value))
      {
        spad_log(message:'ProductRoot determined: ' + obj_rep(value));
        path = ereg_replace(string:value[1], pattern:"\$", replace:"");
      }

      value = RegQueryValue(handle:key_h, item:ver_subkeys[prod]);
      if (!isnull(value))
      {
        spad_log(message:'ProductVersion determined: ' + obj_rep(value));
        ver = value[1];
      }

      # Figure out where to look for signature info.
      #
      # - KAV 15 / 14 / 2010 / 7.0 / 6.0
      if (
        prod_subkeys[prod] == "KasperskyLab\AVP15.0.0\environment" ||
        prod_subkeys[prod] == "KasperskyLab\protected\AVP14.0.0\environment" ||
        prod_subkeys[prod] == "KasperskyLab\protected\AVP9\environment" ||
        prod_subkeys[prod] == "KasperskyLab\protected\AVP7\environment" ||
        prod_subkeys[prod] == "KasperskyLab\AVP6\Environment"
      )
      {
        # Figure out where the update config is.
        value = RegQueryValue(handle:key_h, item:"UpdateRoot");
        if (!isnull(value))
        {
          upd_cfg = value[1];
          upd_cfg = ereg_replace(pattern:"^.+/(.+\.xml)$", replace:"\1", string:upd_cfg);
        }

        data_dir = "%DataFolder%";
        i = 0;
        while (match = pregmatch(pattern:"%([a-zA-Z]+)%", string:data_dir))
        {
          value = NULL;
          if (!isnull(match))
          {
            s = match[1];
            value = RegQueryValue(handle:key_h, item:s);
          }
          if (!isnull(value))
            data_dir = str_replace(
              find:"%" + s + "%",
              replace:value[1],
              string:data_dir
            );
          else break;

          # limit how many times we'll loop.
          if (++i > 5) break;
        }
        if (!isnull(upd_cfg) && !isnull(data_dir)) upd_cfg = data_dir + "\" + upd_cfg;

        base_dir = "%Bases%";
        i = 0;
        while (match = pregmatch(pattern:"%([a-zA-Z]+)%", string:base_dir))
        {
          value = NULL;
          if (!isnull(match))
          {
            s = match[1];
            value = RegQueryValue(handle:key_h, item:s);
          }
          if (!isnull(value))
          {
            base_dir = str_replace(
              find:"%" + s + "%",
              replace:value[1],
              string:base_dir
            );
          }
          else break;

          # limit how many times we'll loop.
          if (++i > 5) break;
        }
      }
      else
      {
        # some products point to it in the registry.
        key2 = "SOFTWARE\KasperskyLab\Components\10a\LastSet";
        key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
        if (!isnull(key2_h))
        {
          value = RegQueryValue(handle:key2_h, item:"Directory");
          if (!isnull(value)) sig_path = ereg_replace(string:value[1], pattern:"\$", replace:"");
        }
        RegCloseKey(handle:key2_h);

        # some products point to it from SS_PRODINFO.xml.
        key2 = "SOFTWARE\KasperskyLab\Components\34";
        key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
        if (!isnull(key2_h))
        {
          value = RegQueryValue(handle:key2_h, item:"SS_PRODINFO");
          if (!isnull(value)) prodinfo = ereg_replace(string:value[1], pattern:"\$", replace:"");
        }
        RegCloseKey(handle:key2_h);
      }
      RegCloseKey(handle:key_h);

      # We found a product so we're done.
      break;
    }
  }
  RegCloseKey(handle:hklm);
  NetUseDel(close:FALSE);
}

if (isnull(name) || isnull(path) || isnull(ver))
{
  NetUseDel();
  audit(AUDIT_NOT_INST,"Kaspersky Antivirus");
}

set_kb_item(name:"Antivirus/Kaspersky/installed", value:TRUE);
set_kb_item(name:"Antivirus/Kaspersky/" + name, value:ver + " in " + path);

dbg::log(src:"kaspersky_installed.nasl",
         msg:'\nupd_cfg:'+upd_cfg+'\nbase_dir:'+base_dir+'\n');

# Figure out where signature information is stored.
update_date = NULL;

# - KAV 7.0 / 6.0
if (!isnull(upd_cfg) && !isnull(base_dir))
{
  # First, read the main updates file.
  NetUseDel();
  contents = hotfix_get_file_contents(path:upd_cfg);
  error = hotfix_handle_error(
      error_code:contents['error'],
      file:upd_cfg,
      appname:name,
      exit_on_fail:FALSE
    );

  if (error)
    spad_log(message:'Error occurred while reading antivirus update file ' + upd_cfg + ': ' + error);
  else
    spad_log(message:'Kaspersky antivirus update file ' + upd_cfg + ' content: ' + obj_rep(contents['data']));

  if (contents['error'] == HCF_OK && !empty_or_null(contents['data']))
  {
    contents = chomp(contents['data']);
    av_upd = NULL;

    if (("AVP14.0.0" >< upd_cfg ||
          "AVP15.0" >< upd_cfg ||
          "KES10SP1" >< upd_cfg ||
          "KES10SP2" >< upd_cfg) &&
        'List="KDB,EMU' >< contents)
    {
      match = pregmatch(pattern:'List="KDB,EMU.+\\.xml\\|([0-9]+ [0-9]+)', string:contents);
      if (!isnull(match))
        update_date = match[1];
    }
    else if (contents && 'UpdateDate="' >< contents)
    {
      contents = strstr(contents, 'UpdateDate="') - 'UpdateDate="';
      contents = contents - strstr(contents, '"');
      update_date = contents;
    }
    else if("AVP9" >< upd_cfg && 'ComponentID="VLNS,KDBI386"' >< contents)
    {
      # nb: File referenced by AVS component does not exist
      #     in AVP9, therefore we use file referenced by
      #     VLNS,KDBI386 to extract update date, which is
      #     accurate.
      contents = strstr(contents, 'ComponentID="VLNS,KDBI386"');
      if (contents) contents = contents - strstr(contents, ">");
      if (contents && 'Filename="' >< contents)
      {
        av_upd = strstr(contents, 'Filename="') - 'Filename="';
        av_upd = av_upd - strstr(av_upd, '"');
      }
    }
    else if ('ComponentID="AVS"' >< contents)
    {
      contents = strstr(contents, 'ComponentID="AVS"');
      if (contents) contents = contents - strstr(contents, ">");
      if (contents && 'Filename="' >< contents)
      {
        av_upd = strstr(contents, 'Filename="') - 'Filename="';
        av_upd = av_upd - strstr(av_upd, '"');
      }
    }
    # AVP 16+, KES10SP1+, KES10SP2
    else if (
      (
        upd_cfg =~ 'AVP(1[6789]|[2-9][0-9])' ||
        'KES' >< upd_cfg ||
        "KSVLA" >< upd_cfg
      ) &&
      'CompID="KDBEFI' >< contents
    )
    {
      tag_open = stridx(contents, "<Update");
      tag_close = stridx(contents, ">");
      if (tag_open >= 0 && tag_close > tag_open)
      {
        contents = substr(contents, tag_open, tag_close);
        match = pregmatch(pattern:'Date="([0-9]+ [0-9]+)"', string:contents);
        if (!isnull(match))
          update_date = match[1];
      }
    }
  }

  dbg::log(src:'kaspersky_installed.nasl',
           msg:'av_upd: '+av_upd);

  # Now grab the AV update file.
  if (!isnull(av_upd) && isnull(update_date))
  {
    NetUseDel();
    xml_file = hotfix_append_path(path:base_dir, value:av_upd);
    contents = hotfix_get_file_contents(path:xml_file);
    error = hotfix_handle_error(
        error_code:contents['error'],
        file:xml_file,
        appname:name,
        exit_on_fail:FALSE
      );

    if (error)
      spad_log(message:'Error occurred while reading antivirus update file ' + xml_file + ': ' + error);
    else
      spad_log(message:'Kaspersky antivirus update file ' + xml_file + ' content: ' + obj_rep(contents['data']));

    if (contents['error'] == HCF_OK && !empty_or_null(contents['data']))
    {
      contents = chomp(contents['data']);
      if ('UpdateDate="' >< contents)
      {
        contents = strstr(contents, 'UpdateDate="') - 'UpdateDate="';
        if (contents) contents = contents - strstr(contents, ">");
        if (contents && '"' >< contents)
          update_date = contents - strstr(contents, '"');
      }
    }
  }
}
else
{
  # Looking for signature file
  if (prodinfo)
  {
    NetUseDel();
    contents = hotfix_get_file_contents(path:prodinfo);
    error = hotfix_handle_error(
        error_code:contents['error'],
        file:prodinfo,
        appname:name,
        exit_on_fail:FALSE
      );

    if (error)
      spad_log(message:'Error occurred while reading product info file ' + prodinfo + ': ' + error);
    else
      spad_log(message:'Kaspersky product info file ' + prodinfo + ' content: ' + obj_rep(contents['data']));

    if (contents['error'] == HCF_OK && !empty_or_null(contents['data']))
    {
      contents = chomp(contents['data']);
      # Isolate the base folder path.
      sig_path = strstr(contents, "BaseFolder");
      if (sig_path)
      {
        len = ord(sig_path[11]);
        if (sig_path) sig_path = substr(sig_path, 12, 12+len-1);
      }
    }
  }

  if (isnull(sig_path))
  {
    # On newer versions, signature may appear in the following file,
    # C:\ProgramData\Kaspersky Lab\Kaspersky Security for Windows Server\11.0\Bases\Current\Stat\kdb.stt
    # File content: 16577712;202104290954
    # 202104290954 being the signature
    if (name == "Kaspersky Security for Windows Server")
    {
      key = "SOFTWARE\Wow6432Node\KasperskyLab\WSEE";
      key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
      if (!isnull(key_h))
      {
        info = RegQueryInfoKey(handle:key_h);
        if (!isnull(info))
        {
          for (i=0; i < info[1]; i++)
          {
            # determine 'version like' subkey which may change in the future
            # example: 11.0
            subkey = RegEnumKey(handle:key_h, index:i);
            spad_log(message:'Reading sub key: ' + subkey);
            if (!empty_or_null(subkey) && subkey =~ "[0-9.]")
            {
              key2_h = RegOpenKey(handle:hklm, key:key+"\"+subkey+"\Environment", mode:MAXIMUM_ALLOWED);
              if (isnull(key2_h))
                continue;

              value = RegQueryValue(handle:key2_h, item:"Bases");
              if (isnull(value))
              {
                RegCloseKey(handle:key2_h);
                continue;
              }

              RegCloseKey(handle:key2_h);
              NetUseDel();

              spad_log(message:'Parsing Kaspersky update db: ' + value[1]);
              contents = hotfix_get_file_contents(path:value[1]);
              error = hotfix_handle_error(
                        error_code:contents['error'],
                        file:value[1],
                        appname:name,
                        exit_on_fail:FALSE
                      );
              if (error)
                spad_log(message:'Error occurred while reading Kaspersky update db: ' + value[1] + ': ' + error);
              else
                spad_log(message:'Kaspersky update db ' + value[1] + ' content: ' + obj_rep(contents['data']));

              if (contents['error'] != HCF_OK || empty_or_null(contents['data']))
                continue;

              contents = chomp(contents['data']);
              match = pregmatch(pattern:";((\d{4})(\d{2})(\d{2})\d{4})$", string:contents);
              if (isnull(match))
                continue;

              spad_log(message:'Found Antivirus Signature (yyyymmddhhmm): ' + obj_rep(match[1]));
              if (!isnull(match[2])) year = match[2];
              if (!isnull(match[3])) month = match[3];
              if (!isnull(match[4])) day = match[4];
              update_date = day +  month + year;

              break;
            }
          }
          RegCloseKey(handle:key_h);
        }
      }
    }
  }

  # Make an assumption to signature file location if is still not found.
  if (isnull(sig_path))
  {
    v = split(ver, sep:'.', keep:FALSE);
    sig_path = "C:\Documents and Settings\All Users\Application Data\" +
               name + "\" +
               v[0] + "." + v[1] +
               "\Bases";
  }

  # Read signature date from the file KAVSET.XML.
  #
  # nb: this is stored typically in a hidden directory, in case one's
  #     simply looking for it.
  NetUseDel();
  contents = hotfix_get_file_contents(path:sig_path);
  error = hotfix_handle_error(
            error_code:contents['error'],
            file:sig_path,
            appname:name,
            exit_on_fail:FALSE
        );

  if (error)
    spad_log(message:'Error occurred while reading signature file ' + sig_path + ': ' + error);
  else
    spad_log(message:'Kaspersky signature file ' + sig_path + ' content: ' + obj_rep(contents['data']));

  if (contents['error'] == HCF_OK && !empty_or_null(contents['data']))
  {
    # Get the date from the update_date XML block.
    update_date = strstr(contents['data'], "Updater/update_date");
    if (update_date) update_date = update_date - strstr(update_date, '" />');
    if (update_date) update_date = strstr(update_date, 'Value="');
    if (update_date) update_date = update_date - 'Value="';
  }
}
NetUseDel();

dbg::log(src:'kaspersky_installed.nasl',
         msg:'update_date: '+update_date);

if (!isnull(update_date) && update_date =~ "^[0-9]+\s*[0-9]+$")
{
  day   = substr(update_date, 0, 1);
  month = substr(update_date, 2, 3);
  year  = substr(update_date, 4, 7);
  sigs_registered = strcat(year, "-", month, "-", day);
  sigs_target = month + "/" + day + "/" + year;
  version_registered = update_date;
}
else
{
  sigs_target = "unknown";
  sigs_registered = "unknown";
  version_registered = "unknown";
}
set_kb_item(name:"Antivirus/Kaspersky/sigs", value:sigs_target);

# Generate report
trouble = 0;

# - general info.
report = "Kaspersky Anti-Virus is installed on the remote host :

  Product name      : " + name + "
  Version           : " + ver + "
  Installation path : " + path + "
  Virus signatures  : " + sigs_target + "

";

# Add vendor 'Kaspersky' if missing
app = name;
if ( app =~ 'Kaspersky' )
  app = 'Kaspersky ' + app; 

register_install(
  app_name : app,
  version  : ver,
  path     : path,
  vendor   : "Kaspersky",
  product  : "Anti-Virus",
  cpe      : cpe
);

# - sigs out-of-date?
info = get_av_info("kaspersky");
if (isnull(info)) exit(1, "Failed to get Kaspersky Anti-Virus info from antivirus.inc.");
sigs_vendor_yyyymmdd = info["sigs_vendor_yyyymmdd"];

out_of_date = 1;
# nb: out_of_date will be 1 if sigs_target == "unknown".
if (sigs_target =~ "[0-9][0-9]/[0-9][0-9]/[0-9][0-9][0-9][0-9]")
{
  a = split(sigs_target, sep:"/", keep:0);
  sigs_target_yyyymmdd = a[2] + a[0] + a[1];

  if (int(sigs_target_yyyymmdd) >= (int(sigs_vendor_yyyymmdd) - 1))
    out_of_date = 0;
}
if (out_of_date)
{
  sigs_vendor_mmddyyyy =
    substr(sigs_vendor_yyyymmdd, 4, 5) +
    "/" +
    substr(sigs_vendor_yyyymmdd, 6, 7) +
    "/" +
    substr(sigs_vendor_yyyymmdd, 0, 3);

  report += "The virus signatures on the remote host are out-of-date - the last
known update from the vendor is " + sigs_vendor_mmddyyyy + "

";
  trouble++;
}

# - services running.
running = "yes";
services = get_kb_item("SMB/svcs");
if (services)
{
  if(
    # Kaspersky Endpoint Security
    "Kaspersky Endpoint Security" >!< services &&
    # Kaspersky Internet Security
    "Kaspersky Internet Security" >!< services &&
    "AVP" >!< services &&
    "avp" >!< services &&
    # others
    "Kaspersky Anti-Virus" >!< services &&
    "kavsvc" >!< services &&
    "KAVFS" >!< services &&
    # Kaspersky Security Center Network Agent
    'klnagent' >!< services
  )
  {
   report += 'The remote Kaspersky Anti-Virus service is not running.\n\n';
   running = "no";
   trouble++;
  }
}
else
{
  report += 'Nessus was unable to retrieve a list of running services from the host.\n\n';
  running = "unknown";
  trouble++;
}

autoupdate_text = "yes";
if(isnull(autoupdate_status)) autoupdate_text = "unknown";
#State=0 means enabled
else if(autoupdate_status != 0) autoupdate_text = "no";

if(!isnull(autoupdate_status) && autoupdate_status != 0)
{
  report += 'Antivirus autoupdate is disabled.\n\n';
  trouble++;
}

security_controls::endpoint::register(
  subtype:'EPP',
  vendor:"Kaspersky",
  product:name,
  product_version:ver,
  cpe:cpe,
  path:path,
  running:running,
  signature_install_date:sigs_registered,
  signature_version:version_registered,
  signature_autoupdate:autoupdate_text
);

# nb: antivirus.nasl uses this in its own report.
set_kb_item (name:"Antivirus/Kaspersky/description", value:report);

if (trouble)
{
  report =
    '\n' +
    report +
    "As a result, the remote host might be infected by viruses.";

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else
{
  exit(0, "Detected Kaspersky Anti-Virus with no known issues to report.");
}
