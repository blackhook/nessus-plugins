#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92438);
  script_version("1.5");
  script_cvs_date("Date: 2018/05/23 16:10:01");

  script_name(english:"WordPad History");
  script_summary(english:"WordPad opened file history.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to gather WordPad opened file history on the remote
host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to generate a report of files opened in WordPad on the
remote host.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/WordPad");
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

key = '\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Wordpad\\Recent File List\\';
wphist = get_hku_key_values(key:key);

att_report = '';
foreach user (keys(wphist))
{
  foreach wpf (keys(wphist[user]))
  {
    if (REPORT_TO_UI) report_extra_output += wphist[user][wpf] + '\n';
    att_report += user+','+key+','+wpf+','+wphist[user][wpf]+'\n';
  }
}

system = get_system_name();

if (strlen(att_report) > 0)
{
  report = report_extra_output+'\nWordPad report attached.\n';

  att_report = 'user,regkey,key,value\n'+att_report;

  attachments[0] = make_array();
  attachments[0]["type"] = "text/csv";
  attachments[0]["name"] = "wordpad_mru_"+system+".csv";
  attachments[0]["value"] = att_report;

  security_report_with_attachments(
    port  : 0,
    level : 0,
    extra : report,
    attachments : attachments
  );  
}
else
{
  exit(0, "No WordPad data found.");
}
