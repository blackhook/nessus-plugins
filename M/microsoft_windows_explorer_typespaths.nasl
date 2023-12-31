#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92418);
  script_version("1.6");
  script_cvs_date("Date: 2018/11/15 20:50:27");

  script_name(english:"Windows Explorer Typed Paths");
  script_summary(english:"Folders that have been visited by manually typed paths."); 

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate the directory paths that users visited by
typing the full directory path into Windows Explorer.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to enumerate the directory paths that users visited by
manually typing the full directory path into Windows Explorer. The
generated folder list report contains folders local to the system,
folders from past mounted network drives, and folders from mounted
devices.");
  # https://www.howtogeek.com/98390/how-to-tweak-the-auto-suggest-feature-in-windows-explorer/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f92f6e9f");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "smb_reg_service_pack.nasl", "set_kb_system_name.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("charset_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("data_protection.inc");

# Disable if GDPR is set
data_protection::disable_plugin_if_set();

REPORT_TO_UI = FALSE;
if (report_verbosity > 0)
{
  REPORT_TO_UI = TRUE;
}
report_extra_output = '';

# HKEY_USERS\\<sid>\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths
key = '\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths';
value = get_hku_key_values(key:key);

att_report = '';
foreach user (keys(value))
{
  foreach tp (value[user])
  {
    if (REPORT_TO_UI) report_extra_output += get_ascii_printable(string:tp) + '\n';
    att_report += user + ',' + get_ascii_printable(string:tp) + '\n';
  }
}

if (strlen(att_report) > 0)
{
  system = get_system_name();

  att_report = 'user,path\n'+att_report;

  attachments[0] = make_array();
  attachments[0]["type"] = "text/csv";
  attachments[0]["name"] = "explorer_typed_paths_"+system+".csv";
  attachments[0]["value"] = att_report;

  report = report_extra_output+'\nExtended explorer typed paths report attached.\n';

  security_report_with_attachments(
    port  : 0,
    level : 0,
    extra : report,
    attachments : attachments
  );
}
else
{
  exit(0, "No explorer typed paths found.");
}
