#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(178102);
 script_version("1.0");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");
 
 script_name(english:"Microsoft Windows Installed Software Version Enumeration");
 
 script_set_attribute(attribute:"synopsis", value:"Enumerates installed software versions.");
 script_set_attribute(attribute:"description", value:'
This plugin enumerates the installed software version by interrogating information obtained from various registry entries
and files on disk. This plugin provides a best guess at the software version and a confidence level for that version.

Note that the versions detected here do not necessarily indicate the actual installed version nor do they necessarily
mean that the application is actually installed on the remote host. In some cases there may be artifacts left behind by
uninstallers on the system.');
 script_set_attribute(attribute:"solution", value:
"Remove any applications that are not compliant with your organization's
acceptable use and security policies.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/10");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_set_attribute(attribute:"agent", value:"windows");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Windows");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_reg_query.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include('http.inc'); #hex2dec

var MAX_INSTALLS = 4000; # unless report verbosity is "Verbose", this is the maximum number of installs/updates reported in the plugin output
var CONFIDENCE_SPECULATIVE = 1;
var CONFIDENCE_LOW = 2;
var CONFIDENCE_MEDIUM = 3;
var CONFIDENCE_HIGH = 4;
var EXE_REGEX = "([A-Za-z]:\\(.*\\)+.*\.(exe|dll))";
var DIR_REGEX = "([A-Za-z]:\\(.*\\)+)";

function set_version_confidence(version, confidence, app_data)
{
  var retval;
  if (empty_or_null(object: app_data.highest_confidence_version))
    retval = {'version':version, 'confidence':confidence, 'other_versions':[version]};
  else 
  {
    var other_versions = app_data.highest_confidence_version.other_versions;
    if (!contains_element(var:other_versions, value:version) )
      append_element(var:other_versions, value:version);
    if ( confidence > app_data.highest_confidence_version.confidence)
    {
      retval = {'version':version, 'confidence':confidence,'other_versions':other_versions};
    }
    else
      retval = {'version':app_data.highest_confidence_version.version, 'confidence':app_data.highest_confidence_version.confidence, 'other_versions':other_versions};
  }
  return retval;
}

function get_file_path_from_string()
{
  var in = _FCT_ANON_ARGS[0];
  var path = NULL;
  if ("MsiExec" >< in)
    return path;
  if ('.exe' >< in || '.dll' >< in)
  {
    path = pregmatch(pattern: EXE_REGEX, string: in);
    if (!empty_or_null(object: path) && !empty_or_null(object: path[0]))
      return path[0];
  }
}

function install_date_helper()
{
  var in = _FCT_ANON_ARGS[0];
  # function exists in case we decide to do date transform
  # or use date to modify confidence in the future
  return in;
}
function install_location_helper()
{
  var path = _FCT_ANON_ARGS[0];
  var version = NULL, error;
  if (!empty_or_null(object: path))
  {
    version = hotfix_get_fversion(path: path);
    error = hotfix_handle_error(error_code:version['error'], file:path);

    if (error && version['error'] != HCF_NOVER)
      dbg::detailed_log(lvl:1, msg:error);

    # No point in saving unknown version
    if(version['error'] != HCF_NOVER)
      version = version['version'];
  }
    # TODO: handle this case.
    # look for exe or dll in path and get their fversion
    # sort | uniq, select something based on criteria
  return version;
}
function display_icon_helper()
{
  var path = _FCT_ANON_ARGS[0];
  var version = NULL, error;
  if (!empty_or_null(object: path))
  {
    version = hotfix_get_fversion(path: path);
    error = hotfix_handle_error(error_code:version['error'], file:path);

    if (error && version['error'] != HCF_NOVER)
      dbg::detailed_log(lvl:1, msg:error);

    # No point in saving unknown version
    if(version['error'] != HCF_NOVER)
      version = version['version'];
  }

  return version;
}
function uninstall_string_helper()
{
  var path = _FCT_ANON_ARGS[0];
  var version = NULL, error;
  if (!empty_or_null(object: path))
  {
    version = hotfix_get_fversion(path: path);
    error = hotfix_handle_error(error_code:version['error'], file:path);

    if (error && version['error'] != HCF_NOVER)
      dbg::detailed_log(lvl:1, msg:error);

    # No point in saving unknown version
    if(version['error'] != HCF_NOVER)
      version = version['version'];
  }

  return version;
}
function version_helper()
{
  var in = _FCT_ANON_ARGS[0];
  var version = NULL;
  #[7070003, 0xe1b7158], # first one is decimal for 7.7.0.3, second is hex for 0e.1b.7158 / 14.27.29016 - try both.
  # could also be already in parsed version format: 114.0.1823.58
  # try splitting on zeros
  # try somehow parsing decimal (yikes)
  #   if %2, prepend a zero, get byte, get byte, get word?
  # try parsing hex
  #   get byte, get byte, get word
  # are all of these byte, byte, 2 byte?

  # It's already a version
  if (typeof(in) == 'string')
    if (pregmatch(pattern: "(\d+\.)+\d+", string: in))
      return in;

  if (typeof(in) == 'int')
    in = ''+in+'';

  if (stridx(in, '0x') == 0)
    in = in - '0x';

  if (strlen(in) % 2 != 0)
    in = '0'+in;

  if (strlen(in) == 8 || (strlen(in) == 10 && stridx(in, '0x') == 0))
  {
    if (pregmatch(pattern: '^[0-9A-Fa-f]+$', string: in))
    {
      in = preg_replace(pattern: "(..)(..)(....)" , replace: "\1.\2.\3", string: in);
      var hexsplit = split(keep: FALSE, sep: '.', in);
      version = strcat(hex2dec(xvalue:hexsplit[0]), '.', hex2dec(xvalue:hexsplit[1]), '.', hex2dec(xvalue:hexsplit[2]));
    }
    else if (pregmatch(pattern: "^[0-9]+$", string: in))
    {
      version = preg_replace(pattern: "(..)(..)(....)" , replace: "\1.\2.\3", string: in);
    }
    # We can also try to handle differentiating between the two if it fits both
    # Add more version parsers here.
  }
  return version;
}

function build_report(apps)
{
  var report = "", app_key, app_val;
  for (var app in apps)
  {
    app_key = app;
    app_val = apps[app_key];
    report += ' - ' + app + '\n';
    report += '     Best Confidence Version  : ' + app_val.highest_confidence_version.version + '\n';
    report += '     Version Confidence Level : ' + app_val.highest_confidence_version.confidence + '\n';
    report += '     All Possible Versions    :  ' + join(app_val.highest_confidence_version.other_versions, sep:', ') + '\n';
    report += '     Other Version Data\n';
    for (var uninstall_key in app_val.data)
    {
      report += '       ['+uninstall_key+'] : \n';
      if (!empty_or_null(object: app_val.data[uninstall_key].raw ))
        report += '           Raw Value           : '+app_val.data[uninstall_key].raw+'\n';
      if (!empty_or_null(object: app_val.data[uninstall_key].parsed_fpath ))
        report += '           Parsed File Path    : '+app_val.data[uninstall_key].parsed_fpath+'\n';
      if (!empty_or_null(object: app_val.data[uninstall_key].parsed_fversion ))
        report += '           Parsed File Version : '+app_val.data[uninstall_key].parsed_fversion+'\n';
      if (!empty_or_null(object: app_val.data[uninstall_key].parsed_version ))
        report += '           Parsed Version : '+app_val.data[uninstall_key].parsed_version+'\n';
    }
    report += '\n';
  }
  return report;
}

var port = kb_smb_transport ();

var uninstall_values = [
  'DisplayName',
  'DisplayVersion',
  'InstallDate',
  'InstallLocation',
  'DisplayIcon',
  'UninstallString',
  'Version',
  'VersionMajor',
  'VersionMinor'
];

# Process each uninstall entries
var display_names = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
var matches, app_key, data, use_app_name, apps = make_array();
for (var key in display_names)
{
  matches = pregmatch(string:key, pattern:"^(.*/)DisplayName$");
  if (isnull(matches)) continue;

  app_key = matches[1];

  # Determine
  data = get_kb_item(key);
  if (!empty_or_null(data))
  {
    use_app_name = data;
    apps[use_app_name]['name']['raw'] = data;
  }
  else
  {
    use_app_name = app_key - 'SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/';
  }

  foreach var uninstall_value (uninstall_values)
  {
    data = get_kb_item(app_key + uninstall_value);
    if (!empty_or_null(data))
      apps[use_app_name]['data'][uninstall_value]['raw'] = data;
  }
}

hotfix_check_fversion_init();
var app_val, path, inner_key, inner_val, parsed_fversion, date;
var installs = 0;
for (var item in apps)
{
  path = NULL;
  parsed_fversion = NULL;
  date = NULL;
  version = NULL;

  if (++installs >= MAX_INSTALLS)
    break;
  app_key = item;
  app_val = apps[app_key];

  for (key in app_val.data)
  {
    inner_key = key;
    inner_val = app_val.data[inner_key];
    switch (inner_key)
    {
      case 'UninstallString':
        if (!empty_or_null(object: inner_val.raw  ))
        {
          path = get_file_path_from_string(inner_val.raw);
          if (!empty_or_null(object: path ))
          {
            apps[app_key]["data"][inner_key].parsed_fpath = path;
            version = uninstall_string_helper(path);
            if (!empty_or_null(object: version))
            {
              apps[app_key]["data"][inner_key].parsed_fversion = version;
              apps[app_key].highest_confidence_version = set_version_confidence(version:version, confidence:CONFIDENCE_MEDIUM, app_data:apps[app_key]);
            }
          }
        }
        break;
      case 'DisplayVersion':
        if (!empty_or_null(object: inner_val.raw  ))
          apps[app_key].highest_confidence_version = set_version_confidence(version:inner_val.raw, confidence:CONFIDENCE_LOW, app_data:apps[app_key]);
        break;
      case 'InstallLocation':
        if (!empty_or_null(object: inner_val.raw  ))
        {
          path = get_file_path_from_string(inner_val.raw);
          if (!empty_or_null(object: path ))
          {
            apps[app_key]["data"][inner_key].parsed_fpath = path;
            version = install_location_helper(path);
            if (!empty_or_null(object: version))
            {
              apps[app_key]["data"][inner_key].parsed_fversion = version;
              apps[app_key].highest_confidence_version = set_version_confidence(version:version, confidence:CONFIDENCE_HIGH, app_data:apps[app_key]);
            }
          }
        }
        break;
      case 'DisplayIcon':
        if (!empty_or_null(object: inner_val.raw  ))
        {
          path = get_file_path_from_string(inner_val.raw);
          if (!empty_or_null(object: path ))
          {
            apps[app_key]["data"][inner_key].parsed_fpath = path;
            version = display_icon_helper(path);
            if (!empty_or_null(object: version))
            {
              apps[app_key]["data"][inner_key].parsed_fversion = version;
              apps[app_key].highest_confidence_version = set_version_confidence(version:version, confidence:CONFIDENCE_MEDIUM, app_data:apps[app_key]);
            }
          }
        }
        break;
      case 'Version':
        if (!empty_or_null(object: inner_val.raw  ))
        {
          parsed_fversion = version_helper(inner_val.raw);
          if (!empty_or_null(object: parsed_fversion))
          {
            apps[app_key]["data"][inner_key].parsed_version = parsed_fversion;
            apps[app_key].highest_confidence_version = set_version_confidence(version:parsed_fversion, confidence:CONFIDENCE_SPECULATIVE, app_data:apps[app_key]);
          }
        }
        break;
      case 'InstallDate':
        if (!empty_or_null(object: inner_val.raw  ))
        {
          date = install_date_helper(inner_val.raw);
          if (!empty_or_null(object: date))
            apps[app_key]["data"][inner_key].date = date;
        }
        break;
      # keys that we don't currently transform:
      case 'VersionMajor':
      case 'VersionMinor':
        break;
      default:
        dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:'Unable to handle key: '+key+'');
        break;
    }
  }
}
hotfix_check_fversion_end();

if(apps)
{
 if (report_verbosity < 2 && len(apps) >= MAX_INSTALLS)
 {
   var report =
     '\nDue to the large number of applications installed, only a partial' +
     '\nlist of software is reported below.  To report all detected' +
     '\napplications, modify the scan policy so that the "Report Verbosity"' +
     '\nis set to "Verbose".\n';
 }
 report += '\nThe following software information is available on the remote host :\n\n' + build_report(apps:apps);

 security_note(extra:report, port:port);
}