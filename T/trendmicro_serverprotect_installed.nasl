#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58580);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/06");

  script_name(english:"Trend Micro ServerProtect Detection and Status (credentialed check)");
  script_summary(english:"Checks for ServerProtect version.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote host, but it is
not working properly.");
  script_set_attribute(attribute:"description", value:
"Trend Micro ServerProtect for Windows, a commercial antivirus and
antimalware software package for Windows, is installed on the remote
host. However, there is a problem with the installation; either its
services are not running or its engine and/or virus definitions are
out of date.");
  # https://www.trendmicro.com/en_us/business/products/user-protection/sps.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36bbbfea");
  script_set_attribute(attribute:"solution", value:
"Make sure that updates are working and the associated services are
running.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Updates to security software are critical.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trendmicro:serverprotect");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"asset_categories", value:"security_control");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "trendmicro_serverprotect_detect.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/Services/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("smb_func.inc");
include("antivirus.inc");
include("security_controls.inc");
include("smb_reg_query.inc");
include("datetime.inc");

#==============================================================#
# Section 1. Utilities                                         #
#==============================================================#

#-------------------------------------------------------#
# Checks the engine version                             #
#-------------------------------------------------------#
function check_pattern_version(data)
{
  local_var idx_start, idx_end, section, pattern;

  pattern = NULL;
  idx_start = stridx(data, 'P.4=pattern');
  if (idx_start >= 0)
    idx_end = stridx(data, 'P.', idx_start+1);

  if (idx_start >= 0 && idx_end > idx_start)
  {
    section = substr(data, idx_start, idx_end);
    section = chomp(section);

    pattern = ereg_replace(string:section, pattern:'P.4=pattern[^,]+,([\\s]+)?([0-9]+).*', replace:"\2");
  }
  return pattern;
}

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit("SMB/Services/Enumerated");

var login   =  kb_smb_login();
var pass    =  kb_smb_password();
var domain  =  kb_smb_domain();
var port    =  kb_smb_transport();

registry_init();

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  close_registry();
  audit(AUDIT_REG_FAIL);
}

# Find where it's installed
var main_key = 'SOFTWARE\\TrendMicro\\ServerProtect\\CurrentVersion';
var path_reg = main_key + '\\HomeDirectory';
path = get_registry_value(handle:hklm, item:path_reg);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, 'TrendMicro ServerProtect');
}

# The following 2 keys are only present on the
# "Information Server" but not the "Normal Server"
var information_server = TRUE; 
var update_key = main_key + '\\Profile\\ActiveUpdate';
var autoupdate_status_reg = update_key + '\\Enable';
var last_update_reg = update_key + '\\LastPerformTime';

var autoupdate_status = get_registry_value(handle:hklm, item:autoupdate_status_reg);
var autoupdate_text = "yes";
if(isnull(autoupdate_status)) autoupdate_text = "unknown";
else if(autoupdate_status == 0) autoupdate_text = "no";

var last_update_unixtime = get_registry_value(handle:hklm, item:last_update_reg);
var last_update_timestamp = NULL;
if(!isnull(last_update_unixtime)) last_update_timestamp = strftime('%F', last_update_unixtime);

if (isnull(autoupdate_status) && isnull(last_update_timestamp))
  information_server = FALSE;

RegCloseKey(handle:hklm);

close_registry(close:FALSE);

# Grab the file version of file SpntSvc.exe

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
exe = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\SpntSvc.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  NetUseDel();
  exit(0, 'Couldn\'t open \''+(share-'$')+':'+exe+'\'.');
}

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);

if (isnull(ver))
{
  NetUseDel();
  audit(AUDIT_VER_FAIL, (share - '$')+':'+exe+'\'.');
}
version = join(ver, sep:'.');

# Get the engine version
engine = NULL;
sys = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\VsapiNT.sys", string:path);
fh = CreateFile(
  file:sys,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (!isnull(fh))
{
  engine = GetFileVersion(handle:fh);
  if (!isnull(engine)) engine = engine[0] + '.' + engine[1] + '.' + engine[3]; # There seems to be an extra 0 in the engine version
  CloseFile(handle:fh);
}

# Try to get various useful information
viruspattern = NULL;
inifile = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\SpntShare\server.ini", string:path);
fh = CreateFile(
  file:inifile,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  if ('x64' >< path)
  {
    inipath = path - 'x64';
    inifile = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\SpntShare\server.ini", string:inipath);
    fh = CreateFile(
      file:inifile,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
  }
}

if (!isnull(fh))
{
  fsize = GetFileSize(handle:fh);
  if (fsize > 10240) fsize = 10240;
  if (fsize)
  {
    data = ReadFile(handle:fh, length:fsize, offset:0);
    CloseFile(handle:fh);
    if (!isnull(data))
      viruspattern = check_pattern_version(data:data);
  }
}
NetUseDel();

# Save the info in the KB
kb_base = "Antivirus/TrendMicro ServerProtect/";
set_kb_item(name:kb_base+"installed", value:TRUE);
if (!isnull(engine))
  set_kb_item(name:kb_base+"trendmicro_engine_version", value:engine);
if (!isnull(viruspattern))
  set_kb_item(name:kb_base+"trendmicro_internal_pattern_version", value:viruspattern);
if (!isnull(version))
  set_kb_item(name:kb_base+"trendmicro_program_version", value:version);

# Determine the info reference key
if (version =~ '^5\\.58\\.')
  refkey = 'spnt558';
else if (version =~ '^5\\.80\\.')
  refkey = 'spnt58';
else if (version =~ '^6\\.')
  refkey = 'spfs60';

# Generate the report.
last_engine_version = '';
info = get_av_info("trendmicro");
if (isnull(info)) exit(1, "Failed to get Trend Micro Antivirus info from antivirus.inc.");
if (refkey)
  last_engine_version = info[refkey]["last_engine_version"];

problems = make_list();
warnings = make_list();
if (isnull(engine)) engine = 'n/a';
if (isnull(viruspattern)) viruspattern = 'n/a';
if (isnull(version)) version = 'n/a';

report =
  '\n' + 'Nessus has gathered the following information about the Trend Micro' +
  '\n' + 'ServerProtect install on the remote host : ' +
  '\n' +
  '\n  Product name      : Trend Micro ServerProtect' +
  '\n  Version           : ' + version +
  '\n  Path              : ' + path +
  '\n  Engine version    : ' + engine +
  '\n  Virus def version : ' + viruspattern +
  '\n  Last update date  : ' + last_update_timestamp +
  '\n  Autoupdate enabled: ' + autoupdate_text +
  '\n';

app = "Trend Micro ServerProtect";
cpe = "cpe:/a:trendmicro:serverprotect";

if (version == 'n/a')
  version = UNKNOWN_VER;

register_install(
  vendor   : "Trend Micro",
  product  : "ServerProtect",
  app_name : app,
  version  : version,
  path     : path,
  cpe      : cpe
);

if (engine == 'n/a')
  problems = make_list(problems, 'The engine version could not be determined.');
else if (information_server)
{
  if (last_engine_version)
  {
    if (engine =~ '^[0-9\\.]+$' && last_engine_version =~ '^[0-9\\.]+$')
    {
      if (ver_compare(ver:engine, fix:last_engine_version, strict:FALSE) < 0)
        problems = make_list(problems, "The virus engine is out-of-date - " + last_engine_version + " is current.");
    }
    else
      problems = make_list(problems, "The engine version is not numeric.");
  }
  else
  {
    item  = 'Nessus does not have information currently about Trend Micro' +
            '\n    ServerProtect ' + version + ' - it may no longer be supported.' +
            '\n';
    problems = make_list(problems, item);
  }
}
else
{
  item = 'Nessus was not able to determine Last update date.';
  warnings = make_list(warnings, item);
  item = 'Nessus was not able to determine Auto update status.';
  warnings = make_list(warnings, item);
}

running = "yes";
services = get_kb_item("SMB/svcs");
if (services)
{
  if ("SpntSvc" >!< services)
  {
    problems = make_list(problems, "The Trend Micro ServerProtect service is not running.");
    running = "no";
  }
}
else
{
  problems = make_list(problems, "Nessus was unable to retrieve a list of running services from the host.");
  running = "unknown";
}

if(isnull(autoupdate_status) && information_server)
{
  problems = make_list(problems, "Nessus was unable to determine AV autoupdate status.");
}
else if(autoupdate_status == 0 && information_server)
{
  problems = make_list(problems, "Autoupdate is disabled in the registry.");
}

security_controls::endpoint::register(
  subtype:'EPP',
  vendor:"Trend Micro",
  product:app,
  product_version:version,
  cpe:cpe,
  path:path,
  running:running,
  signature_autoupdate:autoupdate_text,
  last_checkin:last_update_timestamp
);

if (max_index(problems) > 0)
{
  report += '\n';
  if (max_index(problems) == 1) report += 'One problem was uncovered :\n';
  else report += 'Multiple problems were uncovered :\n';

  foreach problem (problems)
    report += '\n  - ' + problem;

  report += '\n\n' + 'As a result, the host might be infected by viruses.' + '\n';
  security_hole(port:port, extra:report);
}
else if (max_index(warnings) > 0)
{
  report += '\n';
  if (max_index(warnings) == 1) report += 'One warning was uncovered :\n';
  else report += 'Multiple warnings were uncovered :\n';

  foreach warning (warnings)
    report += '\n  - ' + warning;

  report += '\n\n' + 'As a result, the host might be infected by viruses.' + '\n';
  set_kb_item(name:kb_base+"description", value:report);
  exit(0, "Detected Trend Micro ServerProtect.  " + report);
}
else
{
  set_kb_item(name:kb_base+"description", value:report);
  exit(0, "Detected Trend Micro ServerProtect with no known issues to report.");
}
