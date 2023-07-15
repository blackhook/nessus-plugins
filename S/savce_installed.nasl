#
# This script has been rewritten by Montgomery County
# Original script was written by Jeff Adams <jeffadams@comcast.net>
# and Tenable Network Security
# This script is released under GPLv2
#

# Changes by Tenable:
# - Revised plugin title (12/19/09)
# - Revised plugin title (06/14/10)
# - Revised plugin title (02/03/16) since multiple products involved
# - Fixed typos (05/06/14)
# - Added check for product edition (08/06/14)
# - Added a check for if we did not get the services (12/04/14)
# - Added a retrieval of HardwareKey (12/02/03)
# - Minor wording changes in the description block (07/01/16)
# - Added detection for Norton Internet Security (07/21/16)
# - Added support for Symantec Endpoint Protection Cloud and Symantec
# - Endpoint Protection Small Business Edition Cloud (12/21/16)
# - Removed forced software path for 64 bit systems. (04/24/17)
# - Added service check for Norton 360 (06/06/17)
# - Added support for new def file versions (08/02/18)
# - Added support for alternate "current_signature_version" format (01/11/19)
# - Added support for scenario where software is installed
#     but signatures have not been installed/updated (02/04/19)
# - Added support for Symantec SONAR engine version detection (10/7/19)
# - Enhanced support for Symantec SONAR engine version detection (6/8/20)
# - Added security controls kb items (6/15/20)
# - Added date virus definitions were applied (8/9/20)

include("compat.inc");

##
# For plugin debugging, uncomment the following:
# set_kb_item(name:"global_settings/enable_plugin_debugging", value:TRUE);
##


if (description)
{
 script_id(21725);
 script_version("1.1736");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_xref(name:"IAVT", value:"0001-T-0879");

 script_name(english:"Symantec Antivirus Software Detection and Status");
 script_summary(english:"Checks that Symantec antivirus software is installed and the latest virus definitions are loaded.");

 script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote host.");
 script_set_attribute(attribute:"description", value:
"A Symantec antivirus application is installed on the remote host.

Note that this plugin checks that the application is running properly
and that its latest virus definitions are loaded.");
 script_set_attribute(attribute:"solution", value:
"Ensure that updates are working and the associated services are
running.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"manual CVSS score represents risk of having out-of-date virus signatures");

 script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/16");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:antivirus");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:sonar");
 script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
 script_set_attribute(attribute:"asset_categories", value:"security_control");
 script_set_attribute(attribute:"agent", value:"windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2006-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_full_access.nasl", "smb_enum_services.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/transport", "SMB/Services/Enumerated");
 script_require_ports(139, 445);

 exit(0);
}


include("audit.inc");
include("antivirus.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("install_func.inc");
include("spad_log_func.inc");
include("smb_hotfixes_fcheck.inc");
include("security_controls.inc");
include("charset_func.inc");

global_var hklm, sep, def_path, sonar_path, sonar_ver;

#==================================================================#
# Section 1. Utilities                                             #
#==================================================================#

#-------------------------------------------------------------#
# Checks the virus signature version                          #
#-------------------------------------------------------------#
function check_signature_version ()
{
  local_var key, item, items, key_h, val, value, defkeys, paths, path, vers, sig_full, nav;
  local_var key2, key2_h, reg_path;
  paths = make_list();
  defkeys = make_array();
  path = NULL;
  vers = NULL;
  nav = FALSE;

  key = "SOFTWARE\Symantec\InstalledApps\";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
    # NAV check
    value = RegQueryValue(handle:key_h, item:"NAV");
    spad_log(message:'value for NAV: ' + obj_rep(value));
    if( ! isnull(value) )
    {
      spad_log(message:'setting nav to true');
      nav = TRUE;
    }

    # definitions check
    value = RegQueryValue(handle:key_h, item:"AVENGEDEFS");
    spad_log(message:'value for AVENGEDEFS: ' + obj_rep(value));
    if ( ! isnull (value) )
    {
      key = "SOFTWARE\Norton\SharedDefs\";
      key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
      if (! isnull(key_h) )
      {
        path = value[1];
        paths = make_list(paths, path);
        defkeys[path] = 'SOFTWARE\\Norton\\SharedDefs\\';
      }
      else
      {
        key = "SOFTWARE\Symantec\SharedDefs\";
        key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
        if ( ! isnull(key_h) )
        {
          path = value[1];
          paths = make_list(paths, path);
          defkeys[path] = 'SOFTWARE\\Symantec\\SharedDefs\\';
        }
      }
    }
  }
  RegCloseKey (handle:key_h);

  if(nav)
  {
    key = 'SOFTWARE\\Norton\\{0C55C096-0F1D-4F28-AAA2-85EF591126E7}\\Common Client\\PathExpansionMap\\';
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if ( ! isnull(key_h) )
    {
       value = RegQueryValue(handle:key_h, item:'APPDATA');
       spad_log(message:'value for APPDATA: ' + obj_rep(value));
       if ( ! isnull (value) )
       {
         path = value[1];
         paths = make_list(paths, path);
         defkeys[path] = 'SOFTWARE\\Norton\\{0C55C096-0F1D-4F28-AAA2-85EF591126E7}\\SharedDefs\\';

         # Use SharedDefs\SDSDefs if found
         key = defkeys[path] + 'SDSDefs\\';
         key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
         if ( ! isnull(key_h) )
         {
           path = defkeys[path] + 'SDSDefs\\';
           paths = make_list(paths, path);
           defkeys[path] = path;
         }
       }
     RegCloseKey (handle:key_h);
    }
  }
  key = 'SOFTWARE\\Symantec\\Symantec Endpoint Protection\\InstalledApps\\';
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
    spad_log(message:'Symantec Endpoint Protection\\InstalledApps found');
    value = RegQueryValue(handle:key_h, item:'SEPAppDataDir');
    spad_log(message:'value for SEPAppDataDir: ' + obj_rep(value));
    if ( ! isnull(value) )
    {
      path = value[1] + 'Data\\Definitions\\VirusDefs';
      paths = make_list(paths, path);
      defkeys[path] = 'SOFTWARE\\Symantec\\Symantec Endpoint Protection\\CurrentVersion\\SharedDefs';

      path = value[1] + 'Data\\Definitions\\SDSDefs';
      paths = make_list(paths, path);
      defkeys[path] = 'SOFTWARE\\Symantec\\Symantec Endpoint Protection\\CurrentVersion\\SharedDefs\\SDSDefs';
    }
    RegCloseKey (handle:key_h);
  }

  #See if auto-update is enabled
  key = 'SOFTWARE\\Symantec\\Symantec Endpoint Protection\\LiveUpdate\\Schedule\\';
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  update_enabled = 'unknown';
  if ( ! isnull(key_h) )
  {
    spad_log(message:'Symantec Endpoint Protection\\LiveUpdate\\Schedule\n');
    value = RegQueryValue(handle:key_h, item:'Enabled');
    spad_log(message:'value for Enabled: ' + obj_rep(value) + '\n');
    update_enabled = value[1];
    RegCloseKey (handle:key_h);
  }

  if (max_index(paths) == 0)
  {
    spad_log(message:'no paths.  exiting.');
    return NULL;
  }

  foreach path (paths)
  {
    key2 = defkeys[path];
    key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
    if ( ! isnull(key2_h) )
    {
      items = make_list(
        "DEFWATCH_10",
        "NAVCORP_72",
        "NAVCORP_70",
        "NAVNT_50_AP1",
        "AVDEFMGR"
      );

      foreach item (items)
      {
        value = RegQueryValue(handle:key2_h, item:item);
        if (!isnull (value))
        {
          spad_log(message:'value for ' + item + ': ' + obj_rep(value));
          reg_path = 'HKLM\\' + key2 + '\\' + item;
          def_path = value[1];
          val = value[1];
          vers = pregmatch(pattern:"\\([0-9]+)(?:\.[0-9_]+)?$", string:val);
          if (isnull(vers)) 
            vers = val;
          else 
            vers = vers[1];
          spad_log(message:'vers: ' + obj_rep(vers));
        }
      }

      RegCloseKey (handle:key2_h);
    }
  }
  if (isnull(vers))
  {
    spad_log(message:'vers is null.  exiting.'); 
    return NULL;
  }

  sig_full = split(join(def_path), sep:"\");
  sig_full = sig_full[len(sig_full)-1];

  # returning both full and shortened sigs
  set_kb_item(name: "Antivirus/SAVCE/sig_full", value:sig_full);
  set_kb_item(name: "Antivirus/SAVCE/signature", value:vers);
  set_kb_item(name: "Antivirus/SAVCE/signature_path", value:def_path);
  set_kb_item(name: "Antivirus/SAVCE/signature_reg", value:reg_path);

  return mklist(vers, def_path, reg_path, sig_full, update_enabled);
}

#-------------------------------------------------------------#
# Checks AVE version via navex32a.dll                         #
# If DEFWATCH_10 returned a value in check_signature          #
#-------------------------------------------------------------#
function check_ave_version ()
{
  local_var ver, path, fh;


  if(!isnull(def_path))
  {
    path =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\navex32a.dll", string:def_path);

    fh = CreateFile(
      file               : path,
      desired_access     : GENERIC_READ,
      file_attributes    : FILE_ATTRIBUTE_NORMAL,
      share_mode         : FILE_SHARE_READ,
      create_disposition : OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      ver = GetFileVersion(handle:fh);
      ver = join(ver, sep:".");
    }
    if(!isnull(ver)){
      set_kb_item(name: "Antivirus/SAVCE/AVE_version", value:ver);
    }
    CloseFile(handle:fh);
  }

}

#-------------------------------------------------------------#
# Checks the product name                                     #
#-------------------------------------------------------------#

function check_product_name ()
{
  local_var key, item, key_h, value, directory, output, name, vhigh, vlow, v1, v2, v3;

  key = 'SOFTWARE\\Norton\\{0C55C096-0F1D-4F28-AAA2-85EF591126E7}\\';
  item = "PRODUCTNAME";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    name = RegQueryValue(handle:key_h, item:item);
    RegCloseKey(handle:key_h);
    if (!isnull(name))
    {
      set_kb_item(name:'Antivirus/SAVCE/name', value:name[1]);
      return name[1];
    }
  }

 return NULL;
}

#-------------------------------------------------------------#
# Checks the product version                                  #
# Note that major version will only be reported (ie. 9.0.1000 #
#    instead of 9.0.5.1000)                                   #
# Also you can check ProductVersion in                        #
#    HKLM\SOFTWARE\INTEL\LANDesk\VirusProtect6\CurrentVersion #
#-------------------------------------------------------------#

function check_product_version ()
{
  local_var key, item, key_h, value, directory, output, version, vhigh, vlow, v1, v2, v3;

  key = 'SOFTWARE\\Norton\\{0C55C096-0F1D-4F28-AAA2-85EF591126E7}\\';
  item = "PRODUCTVERSION";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    version = RegQueryValue(handle:key_h, item:item);
    RegCloseKey(handle:key_h);
    if (!isnull(version))
    {
      set_kb_item(name:'Antivirus/SAVCE/version', value:version[1]);
      return version[1];
    }
  }

  key = "SOFTWARE\INTEL\LANDesk\VirusProtect6\CurrentVersion";
  item = "ProductVersion";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( isnull(key_h) )
  {
   key = 'SOFTWARE\\Symantec\\Symantec Endpoint Protection\\CurrentVersion';
   key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
   if (!isnull(key_h))
   {
     version = RegQueryValue(handle:key_h, item:item);
     RegCloseKey(handle:key_h);
     if (!isnull(version))
     {
       sep = 1;
       set_kb_item(name:'Antivirus/SAVCE/version', value:version[1]);
       return version[1];
     }
   }
   else
   {
     key = "SOFTWARE\Symantec\Symantec Endpoint Protection\SMC";
     key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
     if (!isnull(key_h))
     {
       version = RegQueryValue(handle:key_h, item:item);
       RegCloseKey(handle:key_h);
       if (!isnull(version))
       {
         sep = 1;
         set_kb_item(name:'Antivirus/SAVCE/version', value:version[1]);
         return version[1];
       }
     }
     key = 'SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV';
     key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
   }
  }

  if ( ! isnull(key_h) )
  {
   version = RegQueryValue(handle:key_h, item:item);

   RegCloseKey (handle:key_h);

   if (!isnull (version))
   {
    vhigh = version[1] & 0xFFFF;
    vlow = (version[1] >>> 16);

    v1 = vhigh / 100;
    v2 = (vhigh%100)/10;
    v3 = (vhigh%10);

    if ( (v1 / 10) > 1 )
    {
      v3 = (v1 / 10 - 1) * 1000;
      v1 = 10 + v1 % 10;
    }

    version = v1 + "." + v2 + "." + v3 + "." + vlow;

    set_kb_item(name: "Antivirus/SAVCE/version", value:version);
    return version;
   }
  }

 return NULL;
}

#-------------------------------------------------------------#
# Checks the product type                                     #
#   sepsb = small business edition                            #
#-------------------------------------------------------------#

function check_product_type ()
{
  local_var key, item, key_h, edition;

  item = "ProductType";
  key = "SOFTWARE\Symantec\Symantec Endpoint Protection\SMC\Common";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    edition = RegQueryValue(handle:key_h, item:item);
    RegCloseKey(handle:key_h);
    if (!isnull(edition))
    {
      set_kb_item(name:'Antivirus/SAVCE/edition', value:edition[1]);
      return edition[1];
    }
  }
  return NULL;
}

#-------------------------------------------------------------#
# Checks if a hotfix has been applied to the host             #
#-------------------------------------------------------------#

function check_for_hotfix ()
{
  local_var key, item, key_h, hotfix;

  item = "HOTFIXREVISION";
  key = "SOFTWARE\Symantec\Symantec Endpoint Protection\CurrentVersion";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    hotfix = RegQueryValue(handle:key_h, item:item);
    RegCloseKey(handle:key_h);
    if (!isnull(hotfix))
    {
      set_kb_item(name:'Antivirus/SAVCE/hotfix_applied', value:hotfix[1]);
      return hotfix[1];
    }
  }
  return NULL;
}

#-------------------------------------------------------------#
# Get Hardware Key (if any)                                   #
#   The Hardware Key is a unique identifier used with SEP     #
#   manager                                                   #
#-------------------------------------------------------------#
function get_hardware_key ()
{
  local_var key, item, key_h, hwid;
  key   = "SOFTWARE\Symantec\Symantec Endpoint Protection\SMC\SYLINK\SyLink";
  item  = "HardwareID";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    hwid = RegQueryValue(handle:key_h, item:item);
    RegCloseKey(handle:key_h);

    if (!isnull(hwid))
      return hwid[1];
  }
  return NULL;
}


#-------------------------------------------------------------#
# Checks the sonar version                                    #
#-------------------------------------------------------------#

function check_sonar_version(sonar_path)
{
  local_var highest_sonar_ver, sonar_ver, path, fh, extra;
  local_var path_parts, assembled_path, ret, patchdir, BHDrvx86_sys_path, BHEngine_dll_path;

  sonar_ver = NULL;
  highest_sonar_ver = NULL;
  if (!isnull(sonar_path))
  {
    path_parts = split(sonar_path, sep:'\\', keep:FALSE);

    if (path_parts[2] == 'Symantec' && path_parts[3] == 'Definitions')
    {
      assembled_path = path_parts[1] + "\\" + path_parts[2] + "\\Symantec Endpoint Protection\\CurrentVersion\\Data\\Definitions\\" + "BASHDefs\\";

      ##
      #  As per https://knowledge.broadcom.com/external/article/177882/how-to-check-the-version-of-av-engine-ip.html
      #  Sonar Engine should be checked from BHDrvx86.sys and/or BHEngine.dll
      #   from "20XXXXXX_XXX" dated patch directories found as subdirectories of BASHDefs (see assembled_path above)
      ##
      ret = list_dir(basedir:assembled_path, level:1, dir_pat:"*", file_pat:"20*", max_recurse:1);
      if (!empty_or_null(ret))
      {
        spad_log(message:'SONAR patch dirs: ' + obj_rep(ret));
        foreach patchdir (ret)
        {
          BHDrvx86_sys_path = patchdir + "\\BHDrvx86.sys";
          fh = CreateFile(
            file               : BHDrvx86_sys_path,
            desired_access     : GENERIC_READ,
            file_attributes    : FILE_ATTRIBUTE_NORMAL,
            share_mode         : FILE_SHARE_READ,
            create_disposition : OPEN_EXISTING
          );
          if (!isnull(fh))
          {
            sonar_ver = GetFileVersion(handle:fh);
            sonar_ver = join(sonar_ver, sep:".");
            if (empty_or_null(highest_sonar_ver) || ver_compare(ver:sonar_ver, fix:highest_sonar_ver, strict:FALSE) == 1)
              highest_sonar_ver = sonar_ver;
          }

          BHEngine_dll_path = patchdir + "\\BHEngine.dll";
          fh = CreateFile(
            file               : BHEngine_dll_path,
            desired_access     : GENERIC_READ,
            file_attributes    : FILE_ATTRIBUTE_NORMAL,
            share_mode         : FILE_SHARE_READ,
            create_disposition : OPEN_EXISTING
          );
          if (!isnull(fh))
          {
            sonar_ver = GetFileVersion(handle:fh);
            sonar_ver = join(sonar_ver, sep:".");
            if (empty_or_null(highest_sonar_ver) || ver_compare(ver:sonar_ver, fix:highest_sonar_ver, strict:FALSE) == 1)
              highest_sonar_ver = sonar_ver;
          }
        }
      }
    }

    if(!isnull(highest_sonar_ver)) {

      spad_log(message:'SONAR version ' + highest_sonar_ver + ' found');
      extra['SONAR Engine Version'] = highest_sonar_ver;
      register_install(
        app_name : "Symantec SONAR",
        vendor : 'Symantec',
        product : 'SONAR',
        version  : highest_sonar_ver,
        path     : sonar_path,
        extra    : extra,
        cpe      : "cpe:/a:symantec:sonar"
      );
    }
    CloseFile(handle:fh);
  }
  return sonar_ver;
}



#==================================================================#
# Section 2. Main code                                             #
#==================================================================#

app = "Symantec Antivirus";
cpe = "cpe:/a:symantec:antivirus";

get_kb_item_or_exit("SMB/registry_full_access");
get_kb_item_or_exit("SMB/Services/Enumerated");

services = get_kb_item("SMB/svcs");

name   = kb_smb_name();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();
port   = kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

#-------------------------------------------------------------#
# Checks if Symantec AntiVirus Corp is installed              #
#-------------------------------------------------------------#

value  = NULL;
value2 = NULL;

key = "SOFTWARE\Symantec\InstalledApps\";
item = "SAVCE";
item2 = "NAV";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 spad_log(message:'value of ' + item + ': ' + obj_rep(value));

 value2 = RegQueryValue(handle:key_h, item:item2);
 spad_log(message:'value of ' + item2 + ': ' + obj_rep(value));
 RegCloseKey (handle:key_h);
}
else
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  audit(AUDIT_NOT_INST, "Symantec Antivirus");
}

if ( isnull ( value ) && isnull (value2) )
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  audit(AUDIT_NOT_INST, "Symantec Antivirus");
}

if(!empty_or_null(value))
  path = value[1];
else if(!empty_or_null(value2))
  path = value2[1];

set_kb_item(name: "Antivirus/SAVCE/installed", value:TRUE);

#-------------------------------------------------------------#
# Checks the virus signature version                          #
#-------------------------------------------------------------#

# Take the first signature version key
signature_array = check_signature_version();

if (isnull(signature_array))
  exit(1, "Unable to obtain signature information from the registry.");

current_signature_version  = signature_array[0];
current_signature_path  = signature_array[1];
current_signature_registry  = signature_array[2];
current_signature_version_full = signature_array[3];
update_enabled = signature_array[4];

#-------------------------------------------------------------#
# Checks if Antivirus is running                              #
#-------------------------------------------------------------#

# Thanks to Jeff Adams for Symantec service.
if ( services )
{
  if (
    ("Norton AntiVirus" >!< services) &&
    (!egrep(pattern:"\[ *Symantec AntiVirus *\]", string:services, icase:TRUE)) &&
    (get_kb_item('SMB/svc/SepMasterService') != SERVICE_ACTIVE) &&
    # Symantec Endpoint Protection Cloud [ SCS ]
    (get_kb_item('SMB/svc/SCS') != SERVICE_ACTIVE) &&
    # Symantec.cloud Endpoint Protection [ ssSpnA ]
    (get_kb_item('SMB/svc/ssSpnAv') != SERVICE_ACTIVE) &&
    # Norton Internet Security
    ("Norton Internet Security" >!< services) &&
    (get_kb_item('SMB/svc/NIS') != SERVICE_ACTIVE) &&
    ("Norton Security" >!< services) &&
    (get_kb_item('SMB/svc/NS') != SERVICE_ACTIVE) &&
    # Symantec Norton 360
    (get_kb_item('SMB/svc/N360') != SERVICE_ACTIVE) &&
    ("Norton 360" >!< services)
  )
    running = 0;
  else
    running = 1;
}

#-------------------------------------------------------------#
# Checks the product version                                  #
#-------------------------------------------------------------#
sep = 0;
product_version = check_product_version();

#-------------------------------------------------------------#
# Checks the product name                                     #
#-------------------------------------------------------------#
product_name = check_product_name();

#-------------------------------------------------------------#
# Checks the product type (if applicable) and                 #
# Check if a hotfix has been applied to the host              #
#-------------------------------------------------------------#
if (sep)
{
  app = "Symantec Endpoint Protection";
  cpe = "cpe:/a:symantec:endpoint_protection";  

  product_type = check_product_type();
  hotfix_applied = check_for_hotfix();
}

#-------------------------------------------------------------#
# Checks to see if this instance of SEP is managed and what   #
# the hardware key                                            #
#-------------------------------------------------------------#
hwid = NULL;
if (sep) hwid = get_hardware_key();

if (!isnull(hwid))
{
  replace_kb_item(name:"Host/Identifiers/Symantec Endpoint Protection Manager", value:hwid);
  replace_kb_item(name:"Host/Identifiers", value:TRUE);
  report_xml_tag(tag:'symantec-ep-hardware-key', value:hwid);
}


#-------------------------------------------------------------#
# Checks if Symantec AntiVirus Corp has Parent server set     #
#-------------------------------------------------------------#

key = "SOFTWARE\Intel\LANDesk\VirusProtect6\CurrentVersion\";
item = "Parent";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 parent = RegQueryValue(handle:key_h, item:item);
 RegCloseKey (handle:key_h);
}

if ( strlen (parent[1]) <=1 )
{
  set_kb_item(name: "Antivirus/SAVCE/noparent", value:TRUE);
}
else
{
  set_kb_item(name: "Antivirus/SAVCE/parent", value:parent[1]);
}


#-------------------------------------------------------------#
# Checks for SONAR Proactive Threat Protection in registry    #
#-------------------------------------------------------------#
sonar_path = NULL;
key = "SOFTWARE\Symantec\SharedDefs\SymcData-spcFerrariBASH\";
item = "SesmInstallApp";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
  sonar_path = RegQueryValue(handle:key_h, item:item);
  if (!empty_or_null(sonar_path) && !empty_or_null(sonar_path[1]))
  {
    sonar_path = sonar_path[1];
    spad_log(message:"SONAR install path from reg: " + obj_rep(sonar_path));
  }
}


#-------------------------------------------------------------#
# Close IPC$ share connection, open C$                        #
#-------------------------------------------------------------#
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"C$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "C$");
}

#-------------------------------------------------------------#
# Check AV Engine version                                     #
#-------------------------------------------------------------#
check_ave_version();

#-------------------------------------------------------------#
# Check Sonar version                                         #
#-------------------------------------------------------------#
if (!empty_or_null(sonar_path))
{
  sonar_ver = check_sonar_version(sonar_path:sonar_path);
}

#==================================================================#
# Section 3. Clean Up                                              #
#==================================================================#
NetUseDel();


#==================================================================#
# Section 4. Final Report                                          #
#==================================================================#

# var initialization
warning = 0;

#
# We first report information about the antivirus
#
report = "The remote host has antivirus software from Symantec installed. It has
been fingerprinted as :

";

if (sep)
{
  product_name = "Symantec Endpoint Protection";
}

report += product_name + " : " + product_version + "
DAT version : " + current_signature_version + "
DAT path    : " + current_signature_path + "
DAT regkey  : " + current_signature_registry + '\n\n';

# Seems this host is managed, report the host guid as well
if (!isnull(hwid))
{
report += 'Hardware key : '+hwid+'\n\n';
}

# If SONAR is present, report this as well
if (!empty_or_null(sonar_ver))
{
report += 'Symantec SONAR engine version : ' + sonar_ver + '\n\n';
}


#
# Check if antivirus signature is up to date
#

# Last Database Version
info = get_av_info("savce");
if (isnull(info)) exit(1, "Failed to get Symantec Antivirus info from antivirus.inc.");
virus = info["virus"];

if (int(current_signature_version) == 0)
{
  ##
  #  current_signature_version sometimes returned in format
  #  C:\ProgramData\Symantec\Symantec Endpoint Protection\14.2.770.0000.105\Data\Definitions\SDSDefs\20181213.008_d2c
  #  ...which will not convert correctly to type int
  ##
  if ("_" >< current_signature_version)
  {
    spad_log(message:'parsing returned current_signature_version from\n' + current_signature_version);
    verparts = split(current_signature_version, sep:'\\');
    verparts = split(verparts[(max_index(verparts) - 1)], sep:'_', keep:FALSE);
    current_signature_version = verparts[0];
    spad_log(message:'to\n' + current_signature_version);
  }

  if (int(current_signature_version) == 0)
    exit(1, "Current signature version returned in unexpected format.");

}

if (int(virus) == 0)
  exit(1, "Virus signature returned in unexpected format.");


if ( int(current_signature_version) < ( int(virus) - 1 ) )
{
  report += "The remote host has an outdated version of virus signatures.
Last version is " + virus + "

";
  warning = 1;
}


#
# Check if antivirus is running
#
if (services && !running)
{
  report += 'The remote ' + product_name + ' is not running.\n\n';
  set_kb_item(name: "Antivirus/SAVCE/running", value:FALSE);
  warning = 1;
}
else if (!services)
{
  report += 'Nessus was unable to retrieve a list of running services from the host.\n\n';
  trouble++;
}
else
{
  set_kb_item(name: "Antivirus/SAVCE/running", value:TRUE);
}

set_kb_item (name:"Antivirus/SAVCE/description", value:report);

#
# Look for date virus definitions were applied in the log files
# LiveUpdate log found in c:\ProgramData\Symantec\LiveUpdate\Log.LiveUpdate
# Lines we are looking for look like 
# 2/12/2017, 16:49:44 GMT -> EVENT - PRODUCT UPDATE SUCCEEDED EVENT - ... Update for CurDefs takes product from update 170211001 to 170212001 ...
# 170211001
# yymmddrrr - r = revision
#
apply_date = NULL;
logpath = 'c:\\ProgramData\\Symantec\\LiveUpdate\\Log.LiveUpdate';
log = hotfix_get_file_contents(logpath);
err = hotfix_handle_error(error_code:log['error'], file:logpath);
if(err)
  spad_log(message:err);
else
{
  #look for update line for currently installed virus defs and grab the time
  formatted_def = current_signature_version_full - '.';
  formatted_def = substr(formatted_def, 2);
  log_line = pregmatch(pattern: "([\d]+/[\d]+/[\d]+),.*PRODUCT UPDATE SUCCEEDED EVENT.*to " + formatted_def + ".*", string: log['data']);
  if(!empty_or_null(log_line))
  {
    #format date from mm/dd/yyyy to yyyy-mm-dd
    apply_date = log_line[1];
    apply_date = split(apply_date, sep:'/', keep:FALSE);
    if(strlen(apply_date[0]) == 1)
      apply_date[0] = '0' + apply_date[0];
    if(strlen(apply_date[1]) == 1)
      apply_date[1] = '0' + apply_date[1];
    apply_date = apply_date[2] + '-' + apply_date[0] + '-' + apply_date[1];
  }
}
#try another location for SEPM Agent
if(empty_or_null(apply_date))
{
  logpath = 'C:\\ProgramData\\Symantec\\Symantec Endpoint Protection\\CurrentVersion\\Data\\Lue\\Logs\\Log.Lue';
  log = hotfix_get_file_contents(logpath);
  err = hotfix_handle_error(error_code:log['error'], file:logpath);
  if(err)
    spad_log(message:err);
  else
  {
    log["data"] = str_replace(string:log["data"], find:'\x00', replace:'');
    #look for update line for currently installed virus defs and grab the time
    formatted_def = current_signature_version_full - '.';
    formatted_def = substr(formatted_def, 2);
    log_line = pregmatch(pattern: " +Update for moniker:[^\n]*Virus Definitions.*SeqNum: " + formatted_def + "(.|[\n])*?Session ended at: ([\d]+/[\d]+/[\d]+).*?", string: log['data']);
    if(!empty_or_null(log_line))
    {
      #format date from yyyy/mm/dd to yyyy-mm-dd
      apply_date = log_line[2];
      apply_date = str_replace(string:apply_date, find:"/", replace:"-");
    }
  }
}

#
# Register security controls info
#
if(empty_or_null(running))
  is_running = 'unknown';
else if(running)
  is_running = 'yes';
else if(!running)
  is_running = 'no';

if(empty_or_null(update_enabled)) 
  autoupdate = 'unknown';
else if(update_enabled)
  autoupdate = 'yes';
else if(!update_enabled)
  autoupdate = 'no';

security_controls::endpoint::register(
  subtype                : 'EPP',
  vendor                 : 'Symantec',
  product                : app,
  product_version        : product_version,
  cpe                    : cpe,
  path                   : path,
  running                : is_running,
  signature_version      : current_signature_version_full,
  signature_install_date : apply_date,
  signature_autoupdate   : autoupdate
);


#
# Create the final report
#

path = current_signature_path;
if (empty_or_null(path))
  path = "unknown";

register_install(
  app_name : app,
  vendor : 'Symantec',
  product : 'SONAR',
  version  : product_version,
  path     : path,
  cpe      : cpe
);

if (warning)
{
  security_report_v4(
    port:port,
    severity:SECURITY_HOLE,
    extra:
      '\n' +
      report +
      'As a result, the remote host might be infected by viruses received by ' +
      'email or other means.'
  );
}
else
{
  exit(0, "Detected " + product_name + " with no known issues to report.");
}
