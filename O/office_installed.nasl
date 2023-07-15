#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(27524);
  script_version("1.163");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/28");

  script_xref(name:"IAVT", value:"0001-T-0505");

  script_name(english:"Microsoft Office Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an office suite.");
  script_set_attribute(attribute:"description", value:
"Microsoft Office is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://products.office.com/en-US/");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42ab6861");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_nt_ms02-031.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("misc_func.inc");
include("install_func.inc");
include("smb_hotfixes_fcheck.inc");
include("office_channel.inc");
include("debug.inc");

# version, sp, file version
var i = 0;
var all_office_versions = {};
var files_info = {};
var files;

# 2000 SP0
all_office_versions[i++] = make_list("Word", "2000", 0, "9.0.0.0");
all_office_versions[i++] = make_list("Excel", "2000", 0, "9.0.0.0");
all_office_versions[i++] = make_list("PowerPoint", "2000", 0, "9.0.0.0");

# 2000 SP1 - no information

# 2000 SP2
all_office_versions[i++] = make_list("Word", "2000", 2, "9.0.0.4527");
all_office_versions[i++] = make_list("Excel", "2000", 2, "9.0.0.4430");
all_office_versions[i++] = make_list("PowerPoint", "2000", 2, "9.0.0.4527");

# 2000 SP3
all_office_versions[i++] = make_list("Word", "2000", 3, "9.0.0.6926");
all_office_versions[i++] = make_list("Excel", "2000", 3, "9.0.0.6627");
all_office_versions[i++] = make_list("PowerPoint", "2000", 3, "9.0.0.6620");

# XP SP0
all_office_versions[i++] = make_list("Word", "XP", 0, "10.0.0.0");
all_office_versions[i++] = make_list("Excel", "XP", 0, "10.0.0.0");
all_office_versions[i++] = make_list("PowerPoint", "XP", 0, "10.0.0.0");

# XP SP1
all_office_versions[i++] = make_list("Word", "XP", 1, "10.0.3416.0");
all_office_versions[i++] = make_list("Excel", "XP", 1, "10.0.3506.0");
all_office_versions[i++] = make_list("PowerPoint", "XP", 1, "10.0.3506.0");

# XP SP2
all_office_versions[i++] = make_list("Word", "XP", 2, "10.0.4219.0");
all_office_versions[i++] = make_list("Excel", "XP", 2, "10.0.4302.0");
all_office_versions[i++] = make_list("PowerPoint", "XP", 2, "10.0.4205.0");

# XP SP3
all_office_versions[i++] = make_list("Word", "XP", 3, "10.0.6612.0");
all_office_versions[i++] = make_list("Excel", "XP", 3, "10.0.6501.0");
all_office_versions[i++] = make_list("PowerPoint", "XP", 3, "10.0.6501.0");

# 2003 SP0
all_office_versions[i++] = make_list("Word", "2003", 0, "11.0.0.0");
all_office_versions[i++] = make_list("Excel", "2003", 0, "11.0.0.0");
all_office_versions[i++] = make_list("PowerPoint", "2003", 0, "11.0.0.0");

# 2003 SP1
all_office_versions[i++] = make_list("Word", "2003", 1, "11.0.6359.0");
all_office_versions[i++] = make_list("Excel", "2003", 1, "11.0.6355.0");
all_office_versions[i++] = make_list("PowerPoint", "2003", 1, "11.0.6361.0");

# 2003 SP2
all_office_versions[i++] = make_list("Word", "2003", 2, "11.0.6568.0");
all_office_versions[i++] = make_list("Excel", "2003", 2, "11.0.6560.0");
all_office_versions[i++] = make_list("PowerPoint", "2003", 2, "11.0.6564.0");

# 2003 SP3
all_office_versions[i++] = make_list("Word", "2003", 3, "11.0.8169.0");
all_office_versions[i++] = make_list("Excel", "2003", 3, "11.0.8169.0");
all_office_versions[i++] = make_list("PowerPoint", "2003", 3, "11.0.8169.0");

# 2007 SP0
all_office_versions[i++] = make_list("Word", "2007", 0, "12.0.0.0");
all_office_versions[i++] = make_list("Excel", "2007", 0, "12.0.0.0");
all_office_versions[i++] = make_list("PowerPoint", "2007", 0, "12.0.0.0");

# 2007 SP1
all_office_versions[i++] = make_list("Word", "2007", 1, "12.0.6215.1000");
all_office_versions[i++] = make_list("Excel", "2007", 1, "12.0.6215.1000");
all_office_versions[i++] = make_list("PowerPoint", "2007", 1, "12.0.6215.1000");

# 2007 SP2
all_office_versions[i++] = make_list("Word", "2007", 2, "12.0.6425.1000");
all_office_versions[i++] = make_list("Excel", "2007", 2, "12.0.6425.1000");
all_office_versions[i++] = make_list("PowerPoint", "2007", 2, "12.0.6425.1000");

# 2007 SP3
all_office_versions[i++] = make_list("Word", "2007", 3, "12.0.6612.1000");
all_office_versions[i++] = make_list("Excel", "2007", 3, "12.0.6611.1000");
all_office_versions[i++] = make_list("PowerPoint", "2007", 3, "12.0.6600.1000");

# 2010 SP0
all_office_versions[i++] = make_list("Word", "2010", 0, "14.0.4762.1000");
all_office_versions[i++] = make_list("Excel", "2010", 0, "14.0.4756.1000");
all_office_versions[i++] = make_list("PowerPoint", "2010", 0, "14.0.4754.1000");

# 2010 SP1
all_office_versions[i++] = make_list("Word", "2010", 1, "14.0.6024.1000");
all_office_versions[i++] = make_list("Excel", "2010", 1, "14.0.6024.1000");
all_office_versions[i++] = make_list("PowerPoint", "2010", 1, "14.0.6026.1000");

# 2010 SP2
all_office_versions[i++] = make_list("Word", "2010", 2, "14.0.7015.1000");
all_office_versions[i++] = make_list("Excel", "2010", 2, "14.0.7015.1000");
all_office_versions[i++] = make_list("PowerPoint", "2010", 2, "14.0.7015.1000");
all_office_versions[i++] = make_list("Project", "2010", 2, "14.0.7015.1000");

# 2013
all_office_versions[i++] = make_list("Word", "2013", 0, "15.0.4420.1017");
all_office_versions[i++] = make_list("Excel", "2013", 0, "15.0.4420.1017");
all_office_versions[i++] = make_list("PowerPoint", "2013", 0, "15.0.4420.1017");
all_office_versions[i++] = make_list("Project", "2013", 0, "15.0.4420.1017");

# 2013 SP1
all_office_versions[i++] = make_list("Word", "2013", 1, "15.0.4569.1504");
all_office_versions[i++] = make_list("Excel", "2013", 1, "15.0.4569.1504");
all_office_versions[i++] = make_list("PowerPoint", "2013", 1, "15.0.4454.1000");
all_office_versions[i++] = make_list("Project", "2013", 1, "15.0.4454.1000");

# 2016 SP0
all_office_versions[i++] = make_list("Word", "2016", 0, "16.0.0.0");
all_office_versions[i++] = make_list("Excel", "2016", 0, "16.0.0.0");
all_office_versions[i++] = make_list("PowerPoint", "2016", 0, "16.0.0.0");
all_office_versions[i++] = make_list("Project", "2016", 0, "16.0.0.0");

# Click-to-Run channel versions
var c2r_ver = retrieve_channel_versions();

# Time of last update history retrieved by Nessus
var build_versions_updated = retrieve_date_updated();

# Supported channel versions
#supported_versions = retrieve_supported_versions();

function office_check_version(v1, v2)
{
  local_var j;

  v1 = split(v1, sep:".", keep:FALSE);
  v2 = split(v2, sep:".", keep:FALSE);

  for (j=0; j<4; j++)
  {
   if (int(v1[j]) > int(v2[j]))
     return 1;
   else if (int(v1[j]) < int(v2[j]))
     return -1;
  }

  return 0;
}


function _retrieve_file_version(path)
{
  var fversion, ver, error;

  fversion = hotfix_get_fversion(path:path);
  error = hotfix_handle_error(error_code:fversion['error'], file:path);
  if(error) dbg::detailed_log(lvl:2, msg:error);

  if (!isnull(fversion.version))
    return fversion.version;

  return NULL;
}


function _append_to_files_info(&files_info, officever, path)
{
  var ver, file_path;

  if (!empty_or_null(path))
  {
    ver = _retrieve_file_version(path:path);
    if (!empty_or_null(ver))
    {
      dbg::detailed_log(lvl:2, msg:'File: ' + path + '\nVersion: ' + ver);
      file_path = str_replace(string:path, find:"\\", replace:"\");

      if (isnull(files_info[officever]))
        files_info[officever] = [];

      append_element(var:files_info[officever], value:{'path': file_path, 'version': ver});
    }

    return NULL;
  }
}


function register_officecommonfiles(major_ver)
{
  var commonfilesdir, files = [], file, bitness;
  if (empty_or_null(major_ver))
  {
    dbg::detailed_log(lvl:1, msg:'Missing required argument "major_ver".');
    return NULL;
  }
  
  commonfilesdir = hotfix_get_officecommonfilesdir(officever:major_ver+'.0');
  if (empty_or_null(commonfilesdir))
  {
    dbg::detailed_log(lvl:1, msg:'Failed to retrieve Office Common Files direcotry. Files under Office Common Files directory won\'t be registered.');
    return NULL;
  }

  files = ['acecore.dll', 'acees.dll', 'aceexcl.dll', 'csi.dll', 'eqnedt32.exe', 
  'mso20win32client.dll', 'mso299lwin32client.dll', 'mso30win32client.dll', 'mso40uiwin32client.dll',
  'mso99lres.dll', 'mso99lwin32client.dll', 'mso.dll', 'msptls.dll', 'ogl.dll'
  'osf.dll', 'riched20.dll', 'vbe7.dll'];

  foreach file (files)
    _append_to_files_info(files_info:files_info, officever:major_ver, path:strcat(commonfilesdir, "\Microsoft Shared\Office", major_ver, "\", file));

  if ( major_ver == '16' )
  {
    bitness = get_kb_item("SMB/Office/16.0/Bitness");
    if (!isnull(bitness))
      _append_to_files_info(files_info:files_info, officever:major_ver, path:strcat("C:\Program Files (", bitness, ")\Microsoft Office\root\VFS\ProgramFilesCommon", bitness, "\Microsoft Shared\Office16\mso.dll"));
  }

  _append_to_files_info(files_info:files_info, officever:major_ver, path:strcat(commonfilesdir, "\Microsoft Shared\EURO\msoeuro.dll"));
  _append_to_files_info(files_info:files_info, officever:major_ver, path:strcat(commonfilesdir, "\Microsoft Shared\PROOF\mssp3gl.dll"));
  _append_to_files_info(files_info:files_info, officever:major_ver, path:strcat(commonfilesdir, "\Microsoft Shared\Source Engine\ose.exe"));
  _append_to_files_info(files_info:files_info, officever:major_ver, path:strcat(commonfilesdir, "\Microsoft Shared\OFFICE", major_ver, "\Office Setup Controller\osetup.dll"));
  _append_to_files_info(files_info:files_info, officever:major_ver, path:strcat(commonfilesdir, "\Microsoft Shared\VBA\VBA7.1\vbe7.dll"));
}

function register_officeprogramfiles(major_ver)
{
  var programfilesdir, files = [], file;

  if (empty_or_null(major_ver))
  {
    dbg::detailed_log(lvl:1, msg:'Missing required argument "major_ver".');
    return NULL;
  }

  programfilesdir = hotfix_get_officeprogramfilesdir(officever:major_ver+'.0');
  if (empty_or_null(programfilesdir))
  {
    dbg::detailed_log(lvl:1, msg:'Failed to retrieve Office Program Files Directory. Files under Office Program Files directory won\'t be registered.');
    return NULL;
  }

  files = ['chart.dll', 'gdiplus.dll', 'gkexcel.dll', 'graph.exe', 'igx.dll',
            'ipeditor.dll', 'msohev.dll', 'oartconv.dll', 'oart.dll', 'offowc.dll',
            'osfproxy.dll', 'usp10.dll', 'wwlibcxm.dll', 'wwlib.dll', 'lync.exe',
            'onenote.exe', 'onenotesyncpc.dll', 'ppcore.dll', 'wordcnv.dll'];

  foreach file (files)
  {
    if ( major_ver == '16' && get_kb_item('SMB/Office/16.0/Channel') != 'MSI' )
      _append_to_files_info(files_info:files_info, officever:major_ver, path:strcat(programfilesdir, "\Microsoft Office\root\Office16\", file));
    else
      _append_to_files_info(files_info:files_info, officever:major_ver, path:strcat(programfilesdir, "\Microsoft Office\Office", major_ver, "\", file));
  }
  _append_to_files_info(files_info:files_info, officever:'15', path:strcat(programfilesdir, "\Microsoft Office\Office15\DCF\office.dll"));
  _append_to_files_info(files_info:files_info, officever:'15', path:strcat(programfilesdir, "\Microsoft Office\Office15\office.dll"));
  _append_to_files_info(files_info:files_info, officever:major_ver, path:strcat(programfilesdir, "\Microsoft Office\Office", major_ver, "\MSIPC\msipc.dll"));
}

function register_miscfiles()
{
  var installs, install, path;

  var sysroot = hotfix_get_systemroot();
  if (empty_or_null(sysroot))
  {
    dbg::detailed_log(lvl:1, msg:'Failed to System Root Directory. Files under system root directory won\'t be registered.');
    return NULL;
  }

  _append_to_files_info(files_info:files_info, officever:'shared', path:sysroot + "\Microsoft.NET\assembly\GAC_MSIL\Microsoft.Office.Visio.Server\v4.0_15.0.0.0__71e9bce111e9429c\Microsoft.Office.Visio.Server.dll");
  _append_to_files_info(files_info:files_info, officever:'shared', path:sysroot + "\Microsoft.NET\assembly\GAC_MSIL\Microsoft.Office.InfoPath.Server\v4.0_15.0.0.0__71e9bce111e9429c\Microsoft.Office.InfoPath.Server.dll");
}


var version = NULL;
var maj_version = NULL;
var installed_office_versions = make_array();
var installed_office_paths = make_array();
var lowest_installed_prod = make_array();
var kb, products, key, sp, project_pattern, project_major_ver, uninstall_keys;
var project_key, project_value, project_match, project_ver_key, split_file_ver, split_reg_ver;
var project_kb_list, project_ver, report_str, prod_version, product_name, product_cpe, product_list;
var pattern, channel, channel_version, channel_build, office_c2r_version, office_c2r_build, office_c2r_channel;
var office_c2r_cdn_url, office_c2r_detection_method, unsupported_date, fields, full_version, ver_parts;
var channel_detect, channel_cdn_url, channel_conflicting_method, channel_supported_versions, len, main_version;
var short_path, app_kb_key, install_kb_key, office_c2r_supported_vers, channel_text, display_channel, report_detail;
var kb_blob, installed_products_by_uuid, installation_paths, installation_vers, office_maj_version;
var path, version_from_uuid, office_version, prod_detail, info, code_pattern, match, channel_detection_method;

######
# Obtain Office product versions from executable files. (set by the dependency smb_nt_ms02-031.nasl)
######
products = make_list( 'Word', 'Excel', 'PowerPoint', 'Project', 'InfoPath', 'OneNote', 'Outlook', 'Access', 'Publisher' );
foreach var product (products)
{
  kb = get_kb_list('SMB/Office/'+product+'/*/ProductPath');
  if ( isnull( kb ) )
    continue;

  foreach var ver( keys(kb) )
  {
    key = ver;
    ver = ver - ('SMB/Office/'+product+'/');
    ver = ver - '/ProductPath';
    
    # Retrieve more accurate version and SP info for Project, if possible
    if (product == "Project")
    {
      # search for Project SP
      project_pattern = "Microsoft( Office)? Project( Standard| Professional) (\d+)";
      project_major_ver = NULL;
      uninstall_keys = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
      project_key = NULL;
      foreach var ukey (keys(uninstall_keys))
      {
        # make sure it's a typical uninstall key
        project_match = pregmatch(string:uninstall_keys[ukey], pattern:project_pattern);
        if (isnull(project_key) && !isnull(project_match) && ukey =~ "Uninstall/{[\w-]+}") 
        {
          project_key = ukey;
          project_major_ver = project_match[3];
          break;
        }
      }
      if (!empty_or_null(project_key))
      {
        project_key = project_key - '/DisplayName';
        project_ver_key = project_key + '/DisplayVersion';
        project_ver = get_kb_item(project_ver_key);
        # first, lets verify it's the same major ver
        split_file_ver = split(ver, sep:'.');
        split_reg_ver = split(project_ver, sep:'.');
        # and then check which version is higher
        if (split_file_ver[0] == split_reg_ver[0] && ver_compare(ver:ver, fix:project_ver, strict:FALSE) < 0)
        {
          ver = project_ver;
          replace_kb_item(name:"SMB/Office/Project/"+ver+"/ProductPath", value:kb[key]);
          # remove older version from KB
          rm_kb_item(name:key);
        }
        # Now try to retrieve SP via uninstall registry key
        project_kb_list = get_kb_list(project_key+"*/DisplayName");
        foreach project_key (keys(project_kb_list))
        {
          project_value = project_kb_list[project_key];
          if ("Service Pack" >< project_value)
          {
            project_match = pregmatch(string:project_value, pattern: "Service Pack (\d)");
            if (!isnull(project_match))
            {
              replace_kb_item(name:"SMB/Project/"+project_major_ver+"/SP",value:project_match[1]);
              sp = project_match[1];
              break;
            }
          }
        }
      }
    }

    report_str = '  - ' + product + ' : ' + ver + '\n';
    prod_version = split( ver, sep:'.', keep:FALSE );
    maj_version = prod_version[0];
    if ( installed_office_versions[ maj_version ] )
    {
      # collect all Office products under the same major version
      installed_office_versions[ maj_version ] += report_str;
      if(ver_compare(ver:ver, fix:lowest_installed_prod[ maj_version ], strict:FALSE) < 0)
        # keep track of the lowerest product version for each major version
        lowest_installed_prod[ maj_version ] = ver;
    }
    else
    {
      installed_office_versions[ maj_version ] = report_str;
      lowest_installed_prod[ maj_version ] = ver;
    }
    # register install path for each major version
    # keep track of the install path of each major version
    # all products share the same major version installed under the same path
    if ( !installed_office_paths[ maj_version ])
    {
      installed_office_paths[ maj_version ] = ereg_replace(pattern:'^(.*)\\\\.*', replace:"\1\", string:kb[key]);
    }

    # registering individual office products
    product_name = "Microsoft "+product;
    product_cpe = "cpe:/a:microsoft:"+tolower(product);
    dbg::log(src:SCRIPT_NAME, msg:"Registering "+product);
    register_install(
      app_name : product_name,
      vendor   : 'Microsoft',
      product  : product,
      version  : ver,
      path     : installed_office_paths[maj_version],
      cpe      : product_cpe
    );
  }
}

######
# Retrieve registry-based info about GPO and C2R office channel
# and store it in the KB. functions coming from office_channel.inc
######

var c2r_reg_version = NULL;
# check if "SMB/Registry/Enumerated" sets to 1
if (check_registry_enumerated())
{
  # Store information under the following registry keys in the kb
  # SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate
  # SOFTWARE\Microsoft\Office\ClickToRun\Configuration
  retrieve_channel_registry_info();
  
  # return the following list based on the kb set in the previous step
  # [major_version, minor_version, installation_path]
  # e.g. [2019, 16.0.9126.2295, "c:..."]
  c2r_reg_version = retrieve_version_via_c2r_registry();
}
# Find update channel, channel version, and channel build for Office 2016
# https://technet.microsoft.com/en-us/library/mt592918.aspx#BKMK_ByDate

product_list = get_kb_list("SMB/Office/*/*/ProductPath");
# Example: SMB/Office/Word/16.0.6001.1073/ProductPath=[path]
pattern = '^SMB/Office/([A-Za-z]+)/([0-9.]+)/ProductPath$';

channel         = NULL;
channel_version = NULL;
channel_build   = NULL;

office_c2r_version          = NULL;
office_c2r_build            = NULL;
office_c2r_channel          = NULL;
office_c2r_cdn_url          = NULL;
office_c2r_detection_method = NULL;

foreach var product_kb (keys(product_list))
{
  unsupported_date = NULL;
  fields = pregmatch(pattern:pattern, string:product_kb, icase:TRUE);

  if (isnull(fields)) continue;
  full_version = fields[2];# 16.0.10359.20023
  if ( full_version !~ "^16\.0" ) continue;
  product_name = fields[1];# Excel

  ver_parts = split(full_version, sep:'.', keep:FALSE);

  # If product is an MSI install, we don't need to check channel version / channel build info
  if (ver_parts[2] >= 4266 && ver_parts[2] < 6001)
  {
    channel = "MSI";
    set_kb_item(name:"SMB/Office/"+product_name+"/16.0/Channel", value:channel);
    if ( product_name == "Word" || product_name == "Excel" )
      office_c2r_channel = channel;
    continue;
  }

  # Third part of full_version correlates to the channel "Version"
  channel_version = c2r_ver[ver_parts[2]];
  if (empty_or_null(channel_version)) channel_version = "unknown";
  channel_build = ver_parts[2] + "." + ver_parts[3];

  # Determine channel based on version or CDN
  # this invokes office_channel.inc/retrieve_update_channel()
  channel_detect = retrieve_update_channel(ver_parts:ver_parts,
                                           c2r_reg_version:c2r_reg_version);
  channel                  = channel_detect['update_channel'];
  if (empty_or_null(channel)) channel = "unknown";
  channel_detection_method = channel_detect['detection_method'];
  if (empty_or_null(channel_detection_method)) channel_detection_method = "";
  channel_cdn_url          = channel_detect['cdn_url'];
  channel_conflicting_method = channel_detect['conflicting_method'];
  channel_supported_versions = channel_detect['supported_versions'];
  # By this point we have :
  # - path
  # - channel
  # Add channel to installed_sw/ data where possible
  if ("Lync" >< product_kb)
  {
    short_path = ereg_replace(string:product_list[product_kb], pattern:"^(.*\\)[^/]+$", replace:"\1");
    app_kb_key = make_app_kb_key(app_name:'Microsoft Lync');
    if (app_kb_key[0] == IF_OK)
    {
      install_kb_key = make_install_kb_key(app_kb_key:app_kb_key[1], path:short_path);
      if (install_kb_key[0] == IF_OK)
        add_extra_to_kb(install_kb_key:install_kb_key[1], extra:make_array('Channel', channel));
    }
  }
  set_kb_item(name:"SMB/Office/"+product_name+"/16.0/Channel", value:channel);
  set_kb_item(name:"SMB/Office/"+product_name+"/16.0/ChannelVersion", value:channel_version);
  set_kb_item(name:"SMB/Office/"+product_name+"/16.0/ChannelBuild", value:channel_build);
  set_kb_item(name:"SMB/Office/"+product_name+"/16.0/ChannelDetectionMethod", value:channel_detection_method);
  set_kb_item(name:"SMB/Office/"+product_name+"/16.0/ChannelCDNUrl", value:channel_cdn_url);
  if (!empty_or_null(channel_supported_versions))
    set_kb_item(name:"SMB/Office/"+product_name+"/16.0/SupportedVersions", value:channel_supported_versions);
  if ( product_name == "Word" || product_name == "Excel" )
  {

    office_c2r_channel          = channel;
    office_c2r_version          = channel_version;
    office_c2r_build            = channel_build;
    office_c2r_detection_method = channel_detection_method;
    office_c2r_cdn_url          = channel_cdn_url;
    office_c2r_supported_vers   = channel_supported_versions;
  }
}
# If we found Office 2016 products but were not able to set Office channel based on Word/Excel, use last product
if ( channel && !office_c2r_channel )
{
  office_c2r_channel = channel;
  if (channel != "MSI")
  {
    office_c2r_version          = channel_version;
    office_c2r_build            = channel_build;
    office_c2r_detection_method = channel_detection_method;
    office_c2r_cdn_url          = channel_cdn_url;
    office_c2r_supported_vers   = channel_supported_versions;
  }
}

if (office_c2r_channel)
{
  # set office365 to true
  if (!get_kb_item("SMB/Office/365")) set_kb_item(name:"SMB/Office/365", value:TRUE);
  # set channel and supportedversions
  set_kb_item(name:"SMB/Office/16.0/Channel", value:office_c2r_channel);
  if (!empty_or_null(office_c2r_detection_method))
    set_kb_item(name:"SMB/Office/16.0/ChannelDetectionMethod", value:office_c2r_detection_method);
  if (!empty_or_null(office_c2r_supported_vers))
    set_kb_item(name:"SMB/Office/16.0/SupportedVersions", value:office_c2r_supported_vers);
  # set channelversion and channelbuild if not MSI install
  if (office_c2r_channel != "MSI")
  {
    set_kb_item(name:"SMB/Office/16.0/ChannelVersion", value:office_c2r_version);
    set_kb_item(name:"SMB/Office/16.0/ChannelBuild", value:office_c2r_build);

    foreach var c (channel_list)
    {
      if ( office_c2r_channel == c.name )
      {
        display_channel = c.display_name;
        break;
      }
    }

    if(!display_channel) display_channel = "unknown";
    channel_text = '';
    if (
        office_c2r_detection_method == "updatechannel" || office_c2r_detection_method == "updatepath"
        || office_c2r_detection_method == "updatebranch" || office_c2r_detection_method == 'productreleaseids'
        )
      channel_text += '\nNessus used the remote host\'s "'+office_c2r_detection_method+'" registry key to determine the update channel :\n';
    else if (office_c2r_detection_method == "buildversion" && !empty_or_null(channel_conflicting_method))
      channel_text += '\nNessus used the remote host\'s "' + channel_conflicting_method + '" registry key to determine the update channel, however the build version indicated a different channel.' +
                      '\nNessus has instead used the remote host\'s office build version to determine the update channel :\n';
    else if (office_c2r_detection_method == "buildversion")
      channel_text += '\nNessus used the remote host\'s office build version to determine the update channel :\n';
    # Display update url from registry values if it was found
    if (!empty_or_null(office_c2r_cdn_url))
      channel_text += '\n  Office Click-to-Run update url     : ' + office_c2r_cdn_url;

    # Display update channel, version, and build
    channel_text +=
                      '\n  Office Click-to-Run update channel : ' + display_channel +
                      '\n  Office Click-to-Run version        : ' + office_c2r_version +
                      '\n  Office Click-to-Run build          : ' + office_c2r_build +
                      '\n';

    # Display the date of the last office history update
    channel_text += '\nNessus last observed a Microsoft Office update on ' + build_versions_updated + '.\n';
  }
}

######
# Here we are looking for Office install in Uninstall key (instead of individual Office product - except for InfoPath)
#
# Examples:
# SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{91150000-0011-0000-0000-0000000FF1CE}/DisplayName=Microsoft Office Professional Plus 2013
# SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/ProfessionalRetail - en-us/DisplayName=Microsoft Office Professional 2016 - en-us
# SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{91150000-0044-0000-0000-0000000FF1CE}/DisplayName=Microsoft InfoPath 2013
######

kb_blob = 'SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName';
installed_products_by_uuid = get_kb_list( kb_blob );
installation_paths = make_array();
installation_vers = make_array();
foreach var uuid ( keys( installed_products_by_uuid ) )
{
  if ( ( installed_products_by_uuid[ uuid ] =~ '^Microsoft (365|Office|InfoPath) ((Apps for (enterprise|business))|2000|XP|[a-zA-Z ]*?(Edition|20[0-2][0-9])|365)' ) &&
       ( ! preg( pattern:"(Media Content|Get Started|Proof|MUI|Communicator|Web Components|Viewer|Primary Interop Assemblies|Access ([0-9]+ )?Runtime|Access database engine|Office [0-9]+ Resource Kit|Visio|OneNote|SharePoint|Project Professional|Project Standard|Visual Web Developer|Interface Pack|Deployment Kit for App-V)",
                 string:installed_products_by_uuid[ uuid ], icase:TRUE ) ) &&
       ('FrontPage' >!< installed_products_by_uuid[uuid] || 'with FrontPage' >< installed_products_by_uuid[uuid]) )
  {
    path = get_kb_item ( str_replace( string:uuid, find:'DisplayName', replace:'InstallLocation'));
    # DisplayVersion
    kb = get_kb_item( str_replace( string:uuid, find:'DisplayName', replace:'DisplayVersion' ) );
    version_from_uuid = kb;
    if ( isnull( kb ) )
      continue;

    office_version = split( kb, sep:'.', keep:FALSE );
    office_maj_version = office_version[0];

    # Check the registry entry against the actual file versions of found product installs
    # go with the file versions (more accurate) if the reg key is lower.
    if (ver_compare(ver:kb, fix:lowest_installed_prod[office_maj_version], strict:FALSE) < 0)
      kb = lowest_installed_prod[office_maj_version];

    if ('The remote host has the following' >< installed_office_versions[office_maj_version])
      continue;
    if (path >!< installed_office_paths[office_maj_version])
      continue;

    prod_detail = installed_office_versions[office_maj_version];
    if (prod_detail && ! empty_or_null(prod_detail))
    {
      len = max_index(keys(all_office_versions));
      for (i=0; i<len; i++)
      {
        info = all_office_versions[i];# e.g. make_list("Word", "2016", 0, "16.0.0.0")
        if (office_check_version(v1:kb, v2:info[3]) >= 0)
          version = i;
      }
      # version is the index here, it is assigned from i above.
      info = all_office_versions[version];

      # use office c2r registy entries in the KB for a more accurate version detection
      # make sure we're comparing the same office installations
      if (!isnull(c2r_reg_version) && version_from_uuid >< c2r_reg_version[1])
      {
        main_version = c2r_reg_version[0];
        installation_vers[office_maj_version] = main_version; # { 16: 2016 }
        report_detail = '\nThe remote host has the following Microsoft Office ' +main_version+' component';
      }
      else
      {
        installation_vers[office_maj_version] = info[1];
        report_detail = '\nThe remote host has the following Microsoft Office ' +info[1]+ ' Service Pack '+ info[2]+' component';
      }

      if ( max_index( split( prod_detail ) ) > 1)
        report_detail += 's';

      report_detail += ' installed :\n\n';
      installed_office_versions[office_maj_version] = report_detail + prod_detail;
      set_kb_item(name:"SMB/Office/"+info[1]+"/SP", value:info[2]);
      sp = info[2];

      if (preg(string:path, pattern:"[^\\]$"))
        path += "\";

      installation_paths[office_maj_version] = path;

      # Save product code.
      code_pattern = "SMB\/Registry\/HKLM\/SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/\{([\w-]+)\}\/DisplayName";
      match = pregmatch(string:uuid, pattern:code_pattern, icase:TRUE);
      if (!isnull(match))
        set_kb_item(name:"SMB/Office/"+info[1]+"/IdentifyingNumber", value:match[1]);
    }
  }
}

if (max_index(keys(installed_office_versions)) == 0)
 exit(0, "No instances of Office were found.");

if (installed_office_versions["16"] && channel_text)
  installed_office_versions["16"] += channel_text;

var app = "Microsoft Office";
var cpe = "cpe:/a:microsoft:office";

var report = NULL;

register_miscfiles();

foreach key ( keys( installed_office_versions ) )
{
  register_officecommonfiles(major_ver:key);
  register_officeprogramfiles(major_ver:key);

  report += installed_office_versions[ key ];

  path = installation_paths[key];
  if (empty_or_null(path)) continue;

  if ( key == '16' )
    path = hotfix_append_path(path:path, value:"root\Office16\");
  else
    path = hotfix_append_path(path:path, value:"\Office" + key);

  if (!isnull(files_info.shared))
    files = make_list(files_info[key], files_info.shared);
  else
    files = files_info[key];

  version = installation_vers[key];
  register_install(
      app_name : app,
      vendor   :'Microsoft',
      product  :installation_vers[key],
      product_version:key,
      update   : string(sp),
      version  : version,
      path     : path,
      files    : files,
      cpe      : cpe
  );
}

var port = get_kb_item("SMB/transport");

security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
