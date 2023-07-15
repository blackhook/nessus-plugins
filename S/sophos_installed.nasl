#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12215);
  script_version("1.1438");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");

  script_name(english:"Sophos Anti-Virus Detection and Status");
  script_summary(english:"Checks for Sophos Anti-Virus.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote host, but it is
not working properly.");
  script_set_attribute(attribute:"description", value:
"Sophos Anti-Virus, a commercial antivirus software package for
Windows, is installed on the remote host. However, there is a problem
with the installation; either its services are not running or its
engine and/or virus definitions are out of date.");
  script_set_attribute(attribute:"see_also", value:"https://www.sophos.com/en-us.aspx");
  script_set_attribute(attribute:"see_also", value:"https://community.sophos.com/kb/en-us/121984");
  script_set_attribute(attribute:"see_also", value:"https://community.sophos.com/kb/en-us/120189");
  script_set_attribute(attribute:"see_also", value:"https://downloads.sophos.com/downloads/info/latest_IDE.xml");
  script_set_attribute(attribute:"solution", value:
"Make sure that updates are working and the associated services are
running.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Updates to security software are critical.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/04/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sophos:sophos_anti-virus");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2004-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sophos_win_installed.nbin");
  script_require_keys("SMB/Services/Enumerated", "Antivirus/Sophos/installed");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("antivirus.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");

get_kb_item_or_exit("SMB/Services/Enumerated");
get_kb_item_or_exit("Antivirus/Sophos/installed");

appname = "Sophos Anti-Virus";

path = get_kb_item("Antivirus/Sophos/path");
prod_ver = get_kb_item("Antivirus/Sophos/prod_ver");
eng_ver = get_kb_item("Antivirus/Sophos/eng_ver");
isUtm = get_kb_item("Antivirus/Sophos/UTM");
isHome = get_kb_item("Antivirus/Sophos/Home");
last_update_date = get_kb_item("Antivirus/Sophos/last_update_date");
has_latest_ide = get_kb_item("Antivirus/Sophos/has_latest_ide"); 
latest_ide_md5_match = get_kb_item("Antivirus/Sophos/latest_ide_md5_match"); 
ide_reason = get_kb_item("Antivirus/Sophos/ide_reason"); 
identity_full_filepath = get_kb_item("Antivirus/Sophos/identity_full_filepath");
cloud_subscription = get_kb_item("Antivirus/Sophos/managed");
autoupdate_running = get_kb_item("Antivirus/Sophos/autoupdate_running");
av_running = get_kb_item("Antivirus/Sophos/av_running");

if (!prod_ver) exit(1, "Failed to get the Sophos Anti-Virus product version.");

## Retrieve antivirus.inc info
if (empty_or_null(cloud_subscription))
{
  av_info = get_av_info("sophos");
}
else
{
  av_info = get_av_info("windows_sophos_managed");
}

if (isnull(av_info)) exit(1, "Failed to get Sophos Anti-Virus info from antivirus.inc.");

# info from antivirus.inc
update_date = av_info["update_date"];
identity_filename = av_info['update_file'];
identity_md5 = av_info['update_md5'];

if (empty_or_null(last_update_date) && 
    (empty_or_null(identity_filename) || 
     empty_or_null(identity_md5)))
{
  exit(1, "Failed to get latest identity file name or MD5 hash from Antivirus.inc.");
}

# Sophos will sometimes have three levels of detail in a single version, sometimes two. Adapting for both.
product_match = pregmatch(pattern:"^([0-9]+\.[0-9]+\.[0-9]+).*$", string:prod_ver);
# Check if we had a result for three levels of depth.
if (isnull(product_match) || isnull(info[product_match[1]]["latest_prod_ver"]))
{
  # Three levels of depth unavailable for this version. Try two!
  product_match = pregmatch(pattern:"^([0-9]+\.[0-9]+).*$", string:prod_ver);
  if (isnull(product_match)) audit(AUDIT_UNKNOWN_APP_VER, appname);
}
prod = product_match[1];

if (isUtm)       appname += " (UTM)";
else if (isHome) appname += " (Home)";

trouble = 0;

# Generate report
# - general info.
info = appname + ' is installed on the remote host :\n' +
       '\n' +
       '  Installation path : ' + path + '\n';

if (prod_ver)
{
  info += '  Product version   : ' + prod_ver + '\n';
}
if (eng_ver)
{
  info += '  Engine version    : ' + eng_ver  + '\n';
}

if (!empty_or_null(last_update_date))
{
  info += '  Virus signatures last updated   : ';
  if (last_update_date) info += substr(last_update_date, 0, 3) + "/" + substr(last_update_date, 4, 5) + "/" + substr(last_update_date, 6, 7) + '\n';
  else info += 'never\n';

  # Check if signatures more than 3 days out of date
  # update date format is YYYYMMDD. last_update_date format is YYYYMMDD.
  report_date = substr(last_update_date, 0, 3) + "/" + substr(last_update_date, 4, 5) + "/" + substr(last_update_date, 6,7);
  vendor_date = substr(update_date, 0, 3) + "/" + substr(update_date, 4, 5) + "/" + substr(update_date, 6,7);
  info += 'Virus signatures last updated   : ' + report_date + '\n';

  latest_time_parts = pregmatch(pattern:"^(\d{4})(\d{2})(\d{2})$", string:update_date);
  if(!isnull(latest_time_parts))
    latest_epoch = mktime(year:int(latest_time_parts[1]), mon:int(latest_time_parts[2]), mday:int(latest_time_parts[3]));
  update_time_parts = pregmatch(pattern:"^(\d{4})(\d{2})(\d{2})$", string:last_update_date);
  if(!isnull(update_time_parts))
    update_epoch = mktime(year:int(update_time_parts[1]), mon:int(update_time_parts[2]), mday:int(update_time_parts[3]));
  three_days = 60*60*24*3;

  if (!isnull(update_epoch))
  {
    # Report if the difference is more than 3 days.
    if ( (latest_epoch - update_epoch) >= three_days)
    {
      trouble++;
      info += '\n' +
              'The virus signatures on the remote host are out-of-date by at least 3 days.\n' +
              'The last update from the vendor was on ' + vendor_date + '.\n';
    }
  }
  else
  {
    trouble++;
    info += '\n' +
            'The virus signatures on the remote host have never been updated!\n' +
            'The last update from the vendor was on ' + vendor_date + '.\n';
  }
}
else
{
  # check to see if we found latest virus identity files (IDE)
  if (has_latest_ide)
  {
    if (!latest_ide_md5_match)
    {
      info += '\n' +
              'The checksum of the latest virus identity file found on the remote host is invalid.\n' +
              'This means that it could have been altered!';
      trouble++;
    }

  }
  else
  {
    info += '\n' + ide_reason; # output reason why latest ide couldn't be found/read
    trouble++;
  }

  if (!isnull(identity_full_filepath))
  {
    info += '\n' +
            '\nNote that Nessus checked for the existence of the following file :\n' +
            "'" + identity_full_filepath + "'" + '\n';
  }
}

# - Check that antivirus service or .exe is running
# - Do the same for autoupdate service
services = get_kb_item("SMB/svcs");
tasklist = get_kb_item("Host/Windows/tasklist_svc");

if (services || tasklist)
{
  if (!av_running)
  {
    info += '\nThe Sophos Anti-Virus service (SAVService) is not running.\n';
    trouble++;
  }
  if(!autoupdate_running)
  {
    info += '\nThe Sophos AutoUpdate Service is not running.\n';
    trouble++;
  }
}
else
{
  info += '\nNessus was unable to retrieve a list of running services from the host.\n';
  trouble++;
}

# nb: antivirus.nasl uses this in its own report.
set_kb_item (name:"Antivirus/Sophos/description", value:info);

if (trouble) info += '\n' +
                     'As a result, the remote host might be infected by viruses.\n';

if (trouble)
{
  report = '\n' + info;
  port = kb_smb_transport(); 
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else
{
  exit(0, "Detected " + appname + " with no known issues to report.");
}
