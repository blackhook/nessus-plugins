#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68997);
  script_version("1.120");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_name(english:"Check Point ZoneAlarm Detection and Status");
  script_summary(english:"Checks for Check Point ZoneAlarm.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote host, but it is
not working properly.");
  script_set_attribute(attribute:"description", value:
"Check Point ZoneAlarm, a commercial antivirus package for Windows, is
installed on the remote host. However, there is a problem with the
installation; either its services are not running or its engine and/or
virus definitions are out of date.");
  script_set_attribute(attribute:"see_also", value:"https://www.zonealarm.com/");
  script_set_attribute(attribute:"solution", value:
"Make sure that updates are working and the associated services are
running.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/22");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:checkpoint:zonealarm");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"asset_categories", value:"security_control");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Updates to security software are critical.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "smb_enum_services.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("antivirus.inc");
include("audit.inc");
include('install_func.inc');
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("security_controls.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');

app = 'Check Point ZoneAlarm';
cpe = 'cpe:/a:checkpoint:zonealarm';

name   = kb_smb_name();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();
port   = kb_smb_transport();

path = NULL;
productname = NULL;
productversion = NULL;
engineversion = NULL;
updatedate = NULL;
running = NULL;

# First get the path
registry_init();
base_key = "SOFTWARE\Zone Labs\ZoneAlarm";
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = base_key + "\InstallDirectory";
path = get_registry_value(handle:hklm, item:key);
if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}

# Get the data directory for the update config
key = "SOFTWARE\KasperskyLab\sdk";
subkeys = get_registry_subkeys(handle:hklm, key:key);
if (!isnull(subkeys))
{
  foreach subkey (subkeys)
  {
    if (subkey =~ '^AVP[0-9]+$')
    {
      key = key + '\\' + subkey + "\environment\Bases";
      upd_cfg = get_registry_value(handle:hklm, item:key);
    }
  }
}

key = base_key + "\CurrentVersion";
productversion = get_registry_value(handle:hklm, item:key);
if (isnull(productversion))
{
  close_registry();
  exit(1, 'Failed to get the version of ' + app);
}

key = base_key + "\Registration" + '\\' + productversion + "\ProductName";
productname = get_registry_value(handle:hklm, item:key);
if (isnull(productname))
{
  close_registry();
  exit(1, 'Failed to get the product name.');
}

set_kb_item(name:"Antivirus/" + app + "/installed", value:TRUE);
set_kb_item(name:"Antivirus/" + app + "/" + productname, value:productversion + " in " + path);

key = base_key + "\AVEngineVer";
engineversion = get_registry_value(handle:hklm, item:key);
if (isnull(engineversion))
{
  close_registry();
  exit(1, 'Failed to get the ' + app + ' engine version.');
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

# Read the update file to get the update date
# Path for new versions is broken, we will try a static path as a backup
# \ProgramData\CheckPoint\ZoneAlarm\Data\avsys\bases_csd\data\u1313g.xml
if (!isnull(upd_cfg))
{
  share = hotfix_path2share(path:upd_cfg);
  xml = ereg_replace(pattern:'^[A-Za-z]:(.*)', string:upd_cfg, replace:"\1\u0607g.xml");

  xml = make_list(xml, "\ProgramData\CheckPoint\ZoneAlarm\Data\avsys\bases_csd\data\u1313g.xml");

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);

  if (rc == 1)
  {
    foreach file (xml)
    {
      fh = CreateFile(
        file:file,
        desired_access:GENERIC_READ,
        file_attributes:FILE_ATTRIBUTE_NORMAL,
        share_mode:FILE_SHARE_READ,
        create_disposition:OPEN_EXISTING
      );
      if (!isnull(fh))
      {
        contents = ReadFile(handle:fh, offset:0, length:10240);
        contents = str_replace(string:contents, find:raw_string(0x00), replace:"");

        # Less strict to catch old and new formats
        if (contents && 'Date="' >< contents)
        {
          if ('UpdateDate="' >< contents)
            contents = strstr(contents, 'UpdateDate="') - 'UpdateDate="';
          else
            contents = strstr(contents, 'Date="') - 'Date="';

          contents = contents - strstr(contents, '"');
          updatedate = contents;
          break;
        }
        CloseFile(handle:fh);
      }
    }
  }
}
NetUseDel();

if (!isnull(updatedate) && updatedate =~ '^[0-9]+( [0-9]+)?$')
{
  day   = substr(updatedate, 0, 1);
  month = substr(updatedate, 2, 3);
  year  = substr(updatedate, 4, 7);
  sigs_target = month + "/" + day + "/" + year;
  signature_install_date = year + "-" + month + "-" + day;
  sigs_target_yyyymmdd = year + month + day;
}
else sigs_target = "unknown";
set_kb_item(name:"Antivirus/" + app + "/sigs", value:sigs_target);

# Generate the report
trouble = 0;

# general info
report =
  '\nCheck Point ZoneAlarm is installed on the remote host :' +
  '\n' +
  '\n  Product name     : ' + productname +
  '\n  Path             : ' + path +
  '\n  Version          : ' + productversion +
  '\n  Engine version   : ' + engineversion +
  '\n  Virus signatures : ' + sigs_target + '\n';

# Check if the signatures are out of date
info = get_av_info("checkpoint");
if (isnull(info)) exit(1, "Failed to get Check Point ZoneAlarm antivirus info from antivirus.inc.");
sigs_vendor_yyyymmdd = info["sigs_vendor_yyyymmdd"];

out_of_date = 1;
# out_of_date will remain 1 if we couldn't get the target signatures
if (sigs_target =~ '^[0-9]{2}/[0-9]{2}/[0-9]{4}$')
{
  if (int(sigs_target_yyyymmdd) >= int(sigs_vendor_yyyymmdd))
    out_of_date = 0;
}
if (out_of_date)
{
  sigs_vendor_mmddyyyy = substr(sigs_vendor_yyyymmdd, 4, 5) + "/" + substr(sigs_vendor_yyyymmdd, 6, 7) + "/" + substr(sigs_vendor_yyyymmdd, 0, 3);
  report +=
    'The virus signatures on the remote host are out-of-date.\n' +
    'The last known update from the vendor is ' + sigs_vendor_mmddyyyy + '.\n';
  trouble++;
}

set_kb_item(name:'Antivirus/' + app + '/description', value:report);

running_svcs = tolower(get_kb_item("SMB/svcs"));
stopped_svcs = tolower(get_kb_item("SMB/svcs/inactive"));

# TESvc = Check Point SandBlast Agent Threat Emulation
# Check Point SandBlast Agent Threat Emulation silently protects your computer from potential malware
if ( tolower('TESvc') >< running_svcs )
  running = 'yes';
else if ( tolower('TESvc') >< stopped_svcs )
  running = 'no';
else
  running = 'unknown';

register_install(
  app_name : app,
  vendor : 'Checkpoint',
  product : 'ZoneAlarm',
  path     : path,
  version  : productversion,
  cpe      : cpe
);

# signature_version takes the form of dd/mm/yyyy for ZoneAlarm
security_controls::endpoint::register(
  subtype                : 'EPP',
  vendor                 : 'CheckPoint',
  product                : productname,
  product_version        : productversion,
  cpe                    : cpe,
  path                   : path,
  running                : running,
  signature_version      : signature_install_date,
  signature_install_date : signature_install_date,
  signature_autoupdate   : 'yes'
);

if (trouble)
{
  report += 'As a result, the remote host might be infected by viruses.';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else
{
  exit(0, "Detected " + app + " with no known issues to report.");
}
