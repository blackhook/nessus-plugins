#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if ( !defined_func("nasl_level") || nasl_level() < 5200 ) exit(0, "Not Nessus 5.2+");

if (description)
{
  script_id(92421);
  script_version("1.5");
  script_cvs_date("Date: 2018/05/16 19:05:10");

  script_name(english:"Internet Explorer Typed URLs");
  script_summary(english:"Report URLs typed into Internet Explorer.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate URLs that were manually typed into the
Internet Explorer address bar.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to generate a list URLs that were manually typed into
the Internet Explorer address bar.");
  script_set_attribute(attribute:"see_also", value:"https://crucialsecurityblog.harris.com/2011/03/14/typedurls-part-1/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
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

REPORT_TO_UI = FALSE;
if (report_verbosity > 0)
{
  REPORT_TO_UI = TRUE;
}
report_extra_output = '';

# HKEY_USERS\\<sid>\\Software\\Microsoft\\Internet Explorer\\TypedURLs
key = '\\Software\\Microsoft\\Internet Explorer\\TypedURLs';
value = get_hku_key_values(key:key);

att_report = '';
foreach user (keys(value))
{
  foreach turl (keys(value[user]))
  {
    att_report += user + ',' + key + ',' + turl + ',' + value[user][turl] +'\n';
    if (REPORT_TO_UI)
    {
      report_extra_output +=  value[user][turl] + '\n';
    }
  }
}

if (strlen(att_report) > 0)
{
  report = report_extra_output+'\nInternet Explorer typed URL report attached.\n';
  att_report = 'user,regkey,key,value\n' + att_report;

  system = get_system_name();

  attachments = make_list();
  attachments[0] = make_array();
  attachments[0]["type"] = "text/csv";
  attachments[0]["name"] = "ie_typedurl_"+system+".csv";
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
  exit(0, "No typed URLs found.");
}
