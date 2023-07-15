#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57793);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");

  script_name(english:"Oracle Fusion Middleware WebLogic Detection (credentialed check)");
  script_summary(english:"Checks for Oracle Fusion Middleware WebLogic.");

  script_set_attribute(attribute:"synopsis", value:
"A web application server is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Oracle WebLogic, a Java EE application, is installed on the remote
host as an Oracle Fusion Middleware component.");
  # https://www.oracle.com/middleware/technologies/weblogic.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2b4620b");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");
include("audit.inc");
include("smb_reg_query.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("install_func.inc");
include("charset_func.inc");
include("spad_log_func.inc");

report_info = "";
install_num = 0;

get_kb_item_or_exit('SMB/Registry/Enumerated');
name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();


# Connect to IPC share on machine
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

# Connect to registry on machine
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

display_names = get_kb_list_or_exit('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');

fusion_installs = make_array();

foreach key (keys(display_names))
{
  display_name = display_names[key];
  if (tolower(display_name) !~ "oracle weblogic")
    continue;

  key = key - 'SMB/Registry/HKLM/' - 'DisplayName';
  key = str_replace(string:key, find:'/', replace:"\");
  key += 'UninstallString';
  path = get_registry_value(handle:hklm, item:key);
  if (!isnull(path))
    fusion_installs[display_name] = path;
}

# this key will only exist in the registry if addtional
# fusion components are installed with WebLogic
key = 'SOFTWARE\\ORACLE';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

oracle_homes = make_list();

if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  if(isnull(info))
  {
    NetUseDel();
    RegCloseKey(handle:hklm);
    exit(1, "Unable to to obtain registry key information.");
  }
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (subkey =~ "KEY_OH.*" || subkey =~ "KEY_OracleHome.*") {
      key2 = key + '\\' + subkey;
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"ORACLE_HOME");
        if (!isnull(value[1]))
          oracle_homes = make_list(oracle_homes, value[1]);
        RegCloseKey(handle:key2_h);
      }
      else
      {
        NetUseDel();
        RegCloseKey(handle:key_h);
        RegCloseKey(handle:hklm);
        exit(1, "Unable to open ORACLE_HOME registry value.");
      }
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (max_index(keys(fusion_installs)) == 0 &&
    max_index(keys(oracle_homes)) == 0)
{
  NetUseDel();
  audit(AUDIT_NOT_INST, "Oracle Fusion Middleware WebLogic Server");
}

### avoid "Error - Multiple sockets connected to port 139/445"
NetUseDel();

if (max_index(keys(fusion_installs)) == 0)
{
  foreach ohome (keys(oracle_homes))
  {
    wlserverloc = oracle_homes[ohome] + "\\wlserver";
    if (hotfix_file_exists(path: wlserverloc))
      fusion_installs["Oracle Weblogic"] = wlserverloc;
  }
}

foreach install (keys(fusion_installs))
{
  middleware_path = "";
  tmp_path = fusion_installs[install];
  if ("uninstall" >< tmp_path)
  {
    # C:\Oracle\Middleware\wlserver_10.3\uninstall\uninstall.cmd
    middleware_path = ereg_replace(pattern:".*([A-Za-z]:.*\\).*\\uninstall\\.*", replace:"\1", string:tmp_path);
  }
  else if ("wlserver" >< tmp_path)
  {
    # C:\Oracle\Middleware\wlserver\
    middleware_path = ereg_replace(pattern:".*([A-Za-z]:.*\\).*\\wlserver", replace:"\1", string:tmp_path);
  }

  if (middleware_path == "")
    continue;

  regxml_path = hotfix_append_path(path: middleware_path, value:"\registry.xml");
  if (hotfix_file_exists(path: regxml_path))
  {
    xml_content = hotfix_get_file_contents(path: regxml_path);
  }
  else
  {
    # version 12 has a slightly different path
    regxml_path = hotfix_append_path(path: middleware_path, value:"\inventory\registry.xml");
    if (hotfix_file_exists(path: regxml_path))
    {
      xml_content = hotfix_get_file_contents(path: regxml_path);
    }
    else
    {
      # file not found for version 11 and version 12
      continue;
    }
  }

  CloseFile(handle:fh);
  # this file should not be empty
  if(xml_content['error'] != HCF_OK)
  {
    NetUseDel();
    spad_log(message:'Unable to obtain contents of registry.xml for Fusion Middleware installed at ' + middleware_path + '.\n');
    continue;
  }

  product_parse = FALSE;
  version_src = "";
  server_src = "";

  foreach line (split(xml_content['data'], sep:'\n', keep:FALSE))
  {
    # version < 12
    if (pregmatch(pattern:'<product[^>]*name=\"WebLogic Platform\"[^>]*>', string:line))
       product_parse = TRUE;
    if (pregmatch(pattern:'</product>', string:line) && product_parse)
      break;
    item = pregmatch(pattern:'<release [^>]*>', string:line);
    if (!isnull(item) && product_parse)
      version_src = item[0];
    item = pregmatch(pattern:'<component[^>]*name=\"WebLogic Server\"[^>]*>', string:line);
    if (!isnull(item) && product_parse)
      server_src = item[0];

    # version >= 12
    if (empty_or_null(server_src))
    {
      if (line =~ "WebLogic Server")
      {
        server_src = line;
        version_src = line;
      }
      if (line =~ "registry home")
        reg_home = line;
    }
  }

  # this shoud be considered an error...
  if (version_src == "" || server_src == "")
  {
    NetUseDel();
    exit(1, 'Unable to extract release or server information from registry.xml.');
  }

  # check to make sure product is completely installed
  item = pregmatch(pattern:'[Ss]tatus=\"([^\"]+)\"', string:version_src);

  if (isnull(item) || tolower(item[1]) != 'installed')
    continue;

  # get server path
  # Luckily, only one WebLogic install is possible per Middleware Home
  item = pregmatch(pattern:'InstallDir=\"([^\"]+)\"', string: server_src);
  if (!isnull(item) && !isnull(item[1]))
    server_path = item[1];
  else if (!empty_or_null(reg_home))
  {
    item = pregmatch(pattern:'registry home=\"([^\"]+)\"', string: reg_home);
    if (!isnull(item) && !isnull(item[1]))
      server_path = item[1] + "\wlserver";
  }
  else
  {
    NetUseDel();
    exit(1, "Unable to extract WebLogic Server path from registry.xml.");
  }
  # grab a list of bug fixes
  bug_fixes = make_list();

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:server_path);
  NetUseDel(close:FALSE);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to '" + share + "' share.") ;
  }

  dir = ereg_replace(pattern:"^[A-Za-z]:(.*)\\?", replace:"\1\bugsfixed", string:server_path);
  fh = FindFirstFile(pattern:dir + "\*-WLS-*");

  while (!isnull(fh[1]))  # loops over each file found in the directory that matches 'pattern'
  {
    item = pregmatch(pattern:"^([0-9]+)-WLS", string:fh[1]);
    if (!isnull(item) && !isnull(item[1]))
       bug_fixes = make_list(bug_fixes, item[1]);
    fh = FindNextFile(handle:fh);  # gets the next file in the directory
  }
  # Remove duplicates
  bug_fixes = list_uniq(bug_fixes);

  version = NULL;
  sp_level = NULL;
  patch_level = NULL;

  # parse version level
  item = pregmatch(pattern:'level=\"([0-9\\.]+)\"', string:version_src);

  if (isnull(item))
    item = pregmatch(pattern:'version=\"([0-9\\.]+)\"', string:version_src);

  if (!isnull(item) && !isnull(item[1]))
    version = item[1];

  # parse service pack level
  item = pregmatch(pattern:'ServicePackLevel=\"([0-9\\.]+)\"', string:version_src);
  if (!isnull(item) && !isnull(item[1]))
    sp_level = item[1];

  # parse patch level
  item = pregmatch(pattern:'PatchLevel=\"([0-9\\.]+)\"', string:version_src);
  if (!isnull(item) && !isnull(item[1]))
    patch_level = item[1];

  # stores a list of oracle homes associated with this fusion install
  fusion_oracle_homes = make_list();

  # verify oracle home directories
  foreach home (oracle_homes)
  {
    # see if home directory is installed as a component of this
    # middleware fusion home
    middleware_path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:middleware_path);
    if(middleware_path >!< home)
      continue;

    # if it's a completely functional home, it will have a
    # inventory\ContentsXML\comps.xml
    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:home);
    NetUseDel(close:FALSE);
    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc != 1)
    {
      NetUseDel();
      exit(1, "Can't connect to '" + share + "' share.") ;
    }

    xml_file = ereg_replace(pattern:"^[A-Za-z]:(.*)\\?", replace:"\1\inventory\ContentsXML\comps.xml", string:home);
    fh = CreateFile(
      file:xml_file,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );

    if(!isnull(fh))
      fusion_oracle_homes = make_list(fusion_oracle_homes, home);
  }

  if (!isnull(version))
  {
    install_num ++;
    report_info += '\n\nFusion Middleware path : ' + middleware_path;
    report_info += '\n  WebLogic Server path : ' + server_path;
    report_info += '\n  Version source       : \n' + version_src;
    report_info += '\n  Version              : ' + version;
    if (!isnull(sp_level))
      report_info += '\n  Service pack         : ' + sp_level;
    if (!isnull(patch_level))
      report_info += '\n  Patch level          : ' + patch_level;

    # makes looping through installs in plugins easier
    set_kb_item(name:"SMB/WebLogic_Fusion/" + install_num + "/Install_Num", value:install_num);

    set_kb_item(name:"SMB/WebLogic_Fusion/" + install_num + "/FusionPath", value:middleware_path);
    set_kb_item(name:"SMB/WebLogic_Fusion/" + install_num + "/ServerPath", value:server_path);
    set_kb_item(name:"SMB/WebLogic_Fusion/" + install_num + "/Version", value:version);
    if (!isnull(sp_level))
      set_kb_item(name:"SMB/WebLogic_Fusion/" + install_num + "/ServicePack", value:sp_level);
    if (!isnull(patch_level))
      set_kb_item(name:"SMB/WebLogic_Fusion/" + install_num + "/PatchLevel", value:patch_level);
    if (max_index(bug_fixes) > 0)
    {
      report_info += '\n  Bug fixes            : ';
      foreach fix (bug_fixes)
      {
        set_kb_item(name:"SMB/WebLogic_Fusion/" + install_num + "/bugfixes/" + fix, value:TRUE);
        report_info += '\n    ' + fix;
      }
    }
    if (max_index(fusion_oracle_homes) > 0)
    {
      report_info += '\n  Component home directories : ';
      i = 0;
      foreach home (fusion_oracle_homes)
      {
        set_kb_item(name:"SMB/WebLogic_Fusion/" + install_num + "/comp_homes/" + i, value:home);
        i++;
        report_info += '\n    ' + home;
      }
    }
  }
}

# Cleanup
NetUseDel();

if(install_num > 0)
{
  set_kb_item(name:"SMB/WebLogic_Fusion/Installed", value:TRUE);
  report_info = data_protection::sanitize_user_paths(report_text:report_info);

  if(install_num == 1)
    report = '\nThe following Fusion Middleware WebLogic install was found :' + report_info + '\n';
  else
    report = '\nThe following Fusion Middleware WebLogic installs were found :' + report_info + '\n';

  if (report_verbosity > 0)
    security_note(port:port, extra:report);
  else security_note(port);

  exit(0);
}
  else exit(0, "No Middleware Fusion Oracle WebLogic installs were found.");
