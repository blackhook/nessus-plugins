#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21608);
  script_version("1.1606");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/06");

  script_name(english:"NOD32 Antivirus Detection and Status");
  script_summary(english:"Checks for NOD32 Antivirus System.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote host, but it is
not working properly.");
  script_set_attribute(attribute:"description", value:
"NOD32 Antivirus, a commercial antivirus software package for Windows,
is installed on the remote host. However, there is a problem with the
installation; either its services are not running or its engine and/or
virus definitions are out of date.");
  script_set_attribute(attribute:"see_also", value:"https://www.eset.com/int/");
  script_set_attribute(attribute:"solution", value:
"Make sure that updates are working and the associated services are
running.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Updates to security software are critical.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:eset_software:nod32_antivirus");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"asset_categories", value:"security_control");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/transport", "SMB/Services/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("antivirus.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("install_func.inc");
include("security_controls.inc");

# 
# Requires open registry connection!
function get_autoupdate_enabled(hive, profile_key)
{
  var status = NULL;

  var active_profile_name = get_registry_value(handle:hive,
    item:profile_key + "\active");
  # No active profile entry = default profile is active = autoupdate is enabled
  if(isnull(active_profile_name)) return TRUE;

  var profile_list_key = profile_key + "\profile";
  var defined_profiles = get_registry_subkeys(handle:hive,
    key:profile_list_key);

  var active_profile_entry = NULL;
  foreach(var profile in defined_profiles)
  {
    var profile_name = get_registry_value(handle:hive,
      item:strcat(profile_list_key, "\", profile, "\name"));
    if(profile_name == active_profile_name)
    {
      active_profile_entry = profile;
      break;
    }
  }
  
   # Non-default active profile is set, but it is not defined - no idea what's the status in this case
  if(isnull(active_profile_entry)) return NULL;

  var update_cfg_key = strcat(profile_list_key, "\", active_profile_entry,
    "\settings\UPDATE_CFG");
  
  status = get_registry_value(handle:hive,
    item:update_cfg_key + "\NotifyBeforeUpdate");
  
  # If the setting does not exist, AV defaults to enabled
  # Otherwise 0 means updates require no user confirmation, so are automatic
  return isnull(status) || status == 0;
}

# Connect to the remote registry.
get_kb_item_or_exit("SMB/Services/Enumerated");

var port = kb_smb_transport();

registry_init();

var hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE);

if(isnull(hklm)) audit(AUDIT_REG_FAIL);

# Check if the software is installed.
var app = "NOD32 Antivirus";
var cpe = "cpe:/a:eset_software:nod32_antivirus";
var path = NULL;
var sigs_date = NULL;
var sigs_formatted = NULL;
var sigs_target_update = NULL;
var version = NULL;
var dates = NULL;
var autoupdate_status = NULL;
var autoupdate_text = "unknown";

var key = "SOFTWARE\ESET\ESET Security\CurrentVersion\Info";
var new_version_used = TRUE;
var profile_key = "SOFTWARE\ESET\ESET Security\CurrentVersion\Config\plugins\01000400\profile";
var install_dir_key = "InstallDir";
var version_key = "ScannerVersion";

var values = get_values_from_key(handle:hklm, entries:[version_key, install_dir_key], key:key);

if(isnull(values))
{
  # In older versions, information was stored
  # in different registry locations, so try that, too.
  new_version_used = FALSE;
  key = "SOFTWARE\Eset\Nod\CurrentVersion\Info";
  profile_key = "SOFTWARE\ESET\Nod\CurrentVersion\Config\plugins\01000400\profile";
  version_key = "CurrentVersion";
  values = get_values_from_key(handle:hklm, entries:[version_key, install_dir_key], key:key);
}

path = values[install_dir_key];
if (!isnull(path))
  path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);

dates = values[version_key];
if(!isnull(dates))
{
  sigs_target_update = ereg_replace(pattern:"^([0-9]+).*", string:dates, replace:"\1");
  sigs_date = ereg_replace(pattern:"^.*\(([0-9]{8})\)", string:dates, replace:"\1");
  sigs_formatted = strcat(substr(sigs_date, 0, 3), "-", substr(sigs_date, 4, 5), "-", substr(sigs_date, 6, 7));
}

autoupdate_status = get_autoupdate_enabled(hive:hklm, profile_key:profile_key);
if(isnull(autoupdate_status)) autoupdate_text = "unknown";
else if (autoupdate_status) autoupdate_text = "enabled";
else autoupdate_text = "disabled";

RegCloseKey(handle:hklm);
close_registry(close:FALSE);

# If we have a path, get the application's version number.
var exe_path = "";
if(!isnull(path))
{
  if(new_version_used)
    exe_path = hotfix_append_path(path:path, value: "egui.exe");
  else
    exe_path = hotfix_append_path(path:path, value: "nod32.exe");
}

if(!empty_or_null(exe_path))
{
  version = hotfix_get_fversion(path:exe_path);
  var error_string = hotfix_handle_error(error_code:version.error,
    file:exe_path, appname:app, exit_on_fail:false);
  
  if(!error_string) 
  {
    version = join(version.value, sep:'.');
  }
  else
  {
    version = NULL;
    spad_log(message:error_string);
  }
}
else
{
  version = NULL;
  spad_log(message:"exe_path is empty, can't get version");
}

hotfix_check_fversion_end();

if (isnull(path) || isnull(sigs_date) || isnull(version)) audit(AUDIT_NOT_INST, "NOD32 Antivirus");

set_kb_item(name:"Antivirus/NOD32/installed", value:TRUE);
set_kb_item(name:"Antivirus/NOD32/version", value:version);
set_kb_item(name:"Antivirus/NOD32/path", value:path);
set_kb_item(name:"Antivirus/NOD32/sigs", value:sigs_target_update + " (" + sigs_date + ")");
set_kb_item(name:"Antivirus/NOD32/autoupdate", value:autoupdate_text);

register_install(
  vendor:"ESET Software",
  product:"NOD32 Antivirus",
  app_name:"NOD32 Antivirus",
  path:path,
  version:version,
  extra:{"Signatures version":sigs_target_update, "Signatures date":sigs_formatted,
  "Autoupdate status":autoupdate_status},
  cpe:cpe
);

# Generate report
var trouble = 0;

# - general info.
var report = "The NOD32 Antivirus System is installed on the remote host :

  Version:           " + version + "
  Installation path: " + path + "
  Virus signatures:  " + sigs_target_update + " 
  Signatures date:   " + sigs_formatted + "
  Autoupdate status: " + autoupdate_text + "

";

# - sigs out-of-date?
var info = get_av_info("nod32");
if (isnull(info)) exit(1, "Failed to get NOD32 Antivirus info from antivirus.inc.");
sigs_vendor_yyyymmdd = info["sigs_vendor_yyyymmdd"];

if (sigs_date =~ "^2[0-9][0-9][0-9][01][0-9][0-3][0-9]")
{
  if (int(sigs_date) < int(sigs_vendor_yyyymmdd))
  {
    report += "The virus signatures on the remote host are out-of-date - the last known" +
      " update from the vendor is " + sigs_vendor_yyyymmdd + '.\n\n';
    trouble++;
  }
}

# Currently we only have a 100% sure detection for
# NotifyBeforeUpdate setting, which forces update confirmation by hand
# Other cases are not exact, so we don't raise an alarm on unknowns
if (autoupdate_status == FALSE)
{
  report += "Current autoupdate status is: " + autoupdate_text + '.\n\n';
  trouble++;
}

# - services running.
var running = "yes";
services = get_kb_item("SMB/svcs");
if (services)
{
  if (
    ("ekrn" >!< services) &&
    (
      "NOD32 Kernel Service" >!< services &&
      "NOD32km" >!< services
    )
  )
  {
    report += 'The remote NOD32 service is not running.\n\n';
    running = "no";
    trouble++;
  }
}
else
{
  report += 'Nessus was unable to retrieve a list of running services from the host.\n\n';
  trouble++;
}

security_controls::endpoint::register(
  subtype                : 'EPP',
  vendor                 : 'ESET',
  product                : app,
  product_version        : version,
  cpe                    : cpe,
  path                   : path,
  running                : running,
  signature_version      : sigs_target_update,
  signature_install_date : sigs_formatted,
  signature_autoupdate   : autoupdate_status
);

# nb: antivirus.nasl uses this in its own report.
set_kb_item (name:"Antivirus/NOD32/description", value:report);

if (trouble) report += "As a result, the remote host might be infected by viruses.";

if (trouble) {
  report = '\n' + report;
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else {
  exit(0, "Detected NOD32 Antivirus with no known issues to report.");
}
