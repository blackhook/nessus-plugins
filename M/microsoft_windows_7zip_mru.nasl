#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if ( !defined_func("nasl_level") || nasl_level() < 5200 ) exit(0, "Not Nessus 5.2+");

if (description)
{
  script_id(92413);
  script_version("1.6");
  script_cvs_date("Date: 2018/11/15 20:50:27");

  script_name(english:"7-Zip Recent Files");
  script_summary(english:"List recently accessed compressed files by 7zip.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate recently accessed 7-Zip compressed files
on the remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to query 7-Zip settings on the remote Windows host to
find recently accessed compressed files.");
  script_set_attribute(attribute:"see_also", value:"https://www.7-zip.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:7-zip:7zip");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2018 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_reg_service_pack.nasl", "set_kb_system_name.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}
include("audit.inc");
include("charset_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("data_protection.inc");

# Disable if data protection is filtering user info
data_protection::disable_plugin_if_set(flags:[data_protection::DPKB_USERNAME]);

# HKEY_USERS\\<sid>\\Software\\7-Zip\\FM : FolderHistory
key = '\\Software\\7-Zip\\FM';
value = get_hku_key_values(key:key, decode:TRUE);

if (isnull(value))
{
  exit(0, "No 7-Zip history returned.");
}

ziphistory = '';
foreach user (keys(value))
{
  folderhistory = value[user]['folderhistory']['ascii'];

  if (empty_or_null(folderhistory)) continue;

  dirs = split(sep:'\\', folderhistory, keep:TRUE);
  ziphistory += user;
  foreach dir (dirs)
  {
    if (':' >< dir)
    {
      ziphistory += '\n - ';
    }
    ziphistory += dir;
  }

  if (strlen(ziphistory) > 0)
  {
    ziphistory += '\n\n';
  }
}

if (strlen(ziphistory) > 0)
{
  security_report_v4(extra:ziphistory, port:0, severity:SECURITY_NOTE);
}
else
{
  exit(0, "No 7-Zip history found.");
}
