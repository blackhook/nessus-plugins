#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(87777);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/26");

  script_name(english:"Avast Antivirus Detection and Status");
  script_summary(english:"Checks for Avast Antivirus.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote host, but it is
not working properly.");
  script_set_attribute(attribute:"description", value:
"Avast Antivirus, a commercial antivirus software package for Windows,
is installed on the remote host. However, there is a problem with the
installation; either its services are not running or its engine and/or
virus definitions are out of date.");
  script_set_attribute(attribute:"see_also", value:"https://www.avast.com/en-us/index");
  script_set_attribute(attribute:"solution", value:
"Make sure that updates are working and the associated services are
running.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"score for product with out-of-date virus definitions");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:avast:antivirus");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"asset_categories", value:"security_control");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/registry_full_access");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("antivirus.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");
include("datetime.inc");
include("security_controls.inc");

get_kb_item_or_exit("SMB/registry_full_access");
get_kb_item_or_exit("SMB/Services/Enumerated");

# Copied wholesale from torture_cgi_func.static.
# Easier to copy for this one plugin than to sort
# out include tree.
function utf16_to_ascii(s)
{
  local_var z, txt;
  # See http://www.w3.org/TR/html4/charset.html#h-5.2.1.1
  txt = str_replace(string: s, find: '\0', replace: '');
  z = substr(txt, 0, 1);
  if (z == '\xFF\xFE' || z == '\xFE\xFF')
    txt = substr(txt, 2);
  return txt;
}

var app_name = "Avast Antivirus";
var exe = "AvastSvc.exe";
var cpe = "cpe:/a:avast:antivirus";
var trouble = 0;
var updateDiff = 0;
var avdefs = 'unknown';
var version, path, last_update, key, file_version, vmain, res;
var last_scan, next_update, last_update_utc, latest_prod_ver;
var configuration, properties, defs, utf16_str, data, latest_sigs_ver, curr_update_date;
var curr_update_parts, curr_update_unix, sig_inst_date;

display_names = get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');

foreach key (keys(display_names))
{
  ##
  # New versions of Avast use the name Avast
  # while older versions use the name avast!
  ##
  if ('Avast Antivirus' >< key || 'avast!' >< display_names[key])
  {
    key = key - 'DisplayName';
    version = get_kb_item(key + 'DisplayVersion');
    path = get_kb_item(key + 'InstallLocation');
    if (empty_or_null(path))
      continue;
    else
      break;
  }
}

if(isnull(path)) audit(AUDIT_NOT_INST, app_name);

file = hotfix_append_path(path:path, value:exe);
file_version = hotfix_get_fversion(path:file);
if (file_version['error'] != HCF_NOVER)
  hotfix_handle_error(error_code:file_version['error'], file:file, appname:app_name, exit_on_fail:TRUE);

# exe_ver['error'] = HCF_OK
if (!isnull(file_version.value))
{
  # Build actual Avast Versions until Apr 27th, 2016
  if (file_version['value'][0] == 11)
    vmain = 2016;
  else if (file_version['value'][0] == 10)
    vmain = 2015;
  else if (file_version['value'][0] == 9)
    vmain = 2014;
  else if (file_version['value'][0] == 8)
    vmain = 2013;

  file_version = join(file_version.value, sep:'.');
  if(isnull(version) || ver_compare(ver:file_version, fix:version, strict:FALSE) == 1)
    version = file_version;
}

# Since 2016-06-21, the product version pattern changed from
# 2016.11.1.2262 -> 12.1.2272 (the year part, i.e. 2016, is removed)
# https://forum.avast.com/index.php?topic=183543.0
if (!isnull(version) && !empty_or_null(vmain))
  version = vmain + "." + version;

if(isnull(version)) version = UNKNOWN_VER;

register_install(
  app_name:app_name,
  vendor : 'Avast',
  product : 'Antivirus',
  path:path,
  version:version,
  cpe:cpe
);

##
# Retrieve AV definition
##
defs = hotfix_append_path(path:path, value:"defs\aswdefs.ini");
properties = hotfix_get_file_contents(path:defs);
res = hotfix_handle_error(error_code:properties["error"], file:defs, appname:app_name);
spad_log(message:"Contents of defs\aswdefs.ini: " + obj_rep(properties));
if(res)
{
  dbg::log(src:SCRIPT_NAME, msg:res);
}
else
{
  data = utf16_to_ascii(s:properties['data']);
  pattern = "Latest=([0-9]+)";
  item = pregmatch(pattern:pattern, string:data);
  if (!isnull(item))
  {
    avdefs = item[1];
    last_update = utctime_to_unixtime(utctime:item[1]);
  }
}

##
# Retrieve lastupdate/nextupdate/lastscan/lastscantime (only available in avast5.ini in older version)
# avast5.ini is renamed to avast5.ini.obsolete in newer versions
##
if (!empty_or_null(vmain))
{
  programdata = hotfix_get_programdata();
  info = hotfix_append_path(path:programdata, value:"\AVAST Software\Avast\avast5.ini");
  configuration = hotfix_get_file_contents(path:info);
  spad_log(message:"Contents of \AVAST Software\Avast\avast5.ini: " + obj_rep(configuration));
  res = hotfix_handle_error(error_code:configuration["error"], file:info, appname:app_name);
  if(res)
  {
    dbg::log(src:SCRIPT_NAME, msg:res);
  }
  else
  {
    data = utf16_to_ascii(s:configuration['data']);
    pattern = "LastUpdate=([0-9]+)";
    item = pregmatch(pattern:pattern, string:data);
    if(!isnull(item))
    {
      last_update = item[1];
      set_kb_item(name:"Antivirus/Avast/lastupdate", value:last_update);
    }

    pattern = "NextUpdate=([0-9]+)";
    item = pregmatch(pattern:pattern, string:data);
    if(!isnull(item))
      set_kb_item(name:"Antivirus/Avast/nextupdate", value:item[1]);

    pattern = "LastScan=([0-9]+)";
    item = pregmatch(pattern:pattern, string:data);
    if(!isnull(item))
      set_kb_item(name:"Antivirus/Avast/lastscan", value:item[1]);

    pattern = "LastScanTime=([0-9]+)";
    item = pregmatch(pattern:pattern, string:data);
    if(!isnull(item))
      set_kb_item(name:"Antivirus/Avast/lastscantime", value:item[1]);
  }
}

# Generate report
report = "The Avast Antivirus System is installed on the remote host :

  Version           : " + version + "
  Installation path : " + path + "
  Virus signatures  : " + avdefs + "
";

info = get_av_info("avast");
if (isnull(info)) exit(1, "Failed to get Avast Antivirus info from antivirus.inc.");

latest_prod_ver = info['win5']["latest_prod_ver"];
latest_sigs_ver = info['latest_sigs_ver'];
curr_update_date = info["update_date"];
latest_sigs_ver = str_replace(string:latest_sigs_ver, find:"-", replace:"0");

if(!empty_or_null(last_update))
  report += "  Last sigs date    : " + strftime('%Y%m%d', int(last_update)) + '\n';

# A check to see if AV signature definitions are up to date.
# This function was tested and works.
if ( avdefs != 'unknown' )
{
  match = pregmatch(pattern:"^(\d{2})(\d{2})(\d{2})\d+$", string:avdefs);
  if(!empty_or_null(match))
    sig_inst_date = '20'+match[1]+'-'+match[2]+'-'+match[3];

  if ( !empty_or_null(latest_sigs_ver) && (int(avdefs) < int(latest_sigs_ver)) )
  {
    report += '\n' +
  'The virus signatures on the remote host are out-of-date. The last ' +
  'known update from the vendor is signature number ' + latest_sigs_ver + '.';
    trouble++;
  }
}

# A check to see if product version is out of date.
if (!empty_or_null(version) && !empty_or_null(latest_prod_ver))
{
  if (ver_compare(ver:version, fix:latest_prod_ver, strict:FALSE) < 0)
  {
    report += '\n' + 'The Avast Antivirus product install is out-of-date. The last known update from the' +
              '\n' + 'the vendor is ' + latest_prod_ver + '.' +
              '\n';
    trouble++;
  }
}

# A check if signatures more than 3 days out of date
curr_update_parts = pregmatch(pattern:"^20(\d{2})(\d{2})(\d{2})$",string:curr_update_date);
if(!empty_or_null(curr_update_parts))
{
  curr_update_unix = utctime_to_unixtime(curr_update_parts[1] + curr_update_parts[2] + curr_update_parts[3] + "000000");
  if(!empty_or_null(last_update))
  {
    updateDiff = int(curr_update_unix) - int(last_update);
    if (int(updateDiff) > 259200)
    {
      trouble++;
      report += '\n' +
            'The virus signatures on the remote host are out-of-date by at least 3 days.\n' +
            'The last update available from the vendor was on ' + curr_update_date  + '.\n';
    }
  }
  else
  {
    trouble++;
    report += '\n' +
          'The virus signatures on the remote host have never been updated!\n' +
          'The last update available from the vendor was on ' + curr_update_date  + '.\n';
  }
}


# - services running.
services = get_kb_item("SMB/svcs");
if (services)
{
  if ("Avast Antivirus" >!< services)
  {
    report += '\nThe Avast Antivirus service (avast! Antivirus) is not running.\n';
    trouble++;
    running = 'no';
  }
  else
  {
    running = 'yes';
  }
}
else
{
  report += '\nNessus was unable to retrieve a list of running services from the host.\n';
  trouble++;
}

if (trouble) report += '\n' +
                     'As a result, the remote host might be infected by viruses.\n';

set_kb_item(name:"Antivirus/Avast/installed", value:TRUE);
set_kb_item(name:"Antivirus/Avast/version", value:version);
set_kb_item(name:"Antivirus/Avast/path", value:path);
set_kb_item(name:"Antivirus/Avast/avdefs", value:avdefs);
# nb: antivirus.nasl uses this in its own report.
set_kb_item(name:"Antivirus/Avast/description", value:report);

security_controls::endpoint::register(
  subtype                : 'EPP',
  vendor                 : 'Avast',
  product                : 'Avast Antivirus',
  product_version        : version,
  cpe                    : cpe,
  path                   : path,
  running                : running,
  signature_version      : avdefs,
  signature_install_date : sig_inst_date
);

hotfix_check_fversion_end();
port = kb_smb_transport();

if (trouble)
{
  report = '\n' + report ;
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report) ;
}
else
{
  exit(0, "Detected Avast Antivirus with no known issues to report.");
}
