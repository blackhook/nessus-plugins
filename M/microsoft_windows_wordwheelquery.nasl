#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92439);
  script_version("1.6");
  script_cvs_date("Date: 2018/11/15 20:50:27");

  script_name(english:"Explorer Search History");
  script_summary(english:"Windows explorer search history report.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to gather a list of items searched for in the Windows
UI.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to gather evidence of cached search results from
Windows Explorer searches.");
  script_set_attribute(attribute:"see_also", value:"https://www.4n6k.com/2015/05/forensics-quickie-ntuserdat-analysis.html");
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



# HKEY_USERS\\<sid>\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery
key = '\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery';
value = get_hku_key_values(key:key, decode:TRUE);

wwq_report = '';
foreach user (keys(value))
{
  foreach files (keys(value[user]))
  {
    user = format_for_csv(data:user);
    key = format_for_csv(data:key);
    files = format_for_csv(data:files);
    raw = format_for_csv(data:value[user][files]['raw']);
    ascii = format_for_csv(data:value[user][files]['ascii']);
    hex = value[user][files]['hex'];

    if (REPORT_TO_UI && isnull(int(key)) && int(key) > 0)
    {
      report_extra_output += ascii + '\n';
    }

    wwq_report += '"'+user+'","'+key+'","'+files+'","'+ raw + '","' + ascii +  '","' + hex +'"\n';
  }
}

if (strlen(wwq_report) > 0)
{
  report = report_extra_output+'\nExplorer search history report attached.\n';

  wwq_report = 'user,regkey,key,raw,ascii,hex\n' + wwq_report;

  system = get_system_name();

  attachments = make_list();
  attachments[0] = make_array();
  attachments[0]["type"] = "text/csv";
  attachments[0]["name"] = "explorer_search_history_"+system+".csv";
  attachments[0]["value"] = wwq_report;

  security_report_with_attachments(
    port  : 0,
    level : 0,
    extra : report,
    attachments : attachments
  );
}
else
{
  exit(0, "No WordWheel query entries found.");
}
