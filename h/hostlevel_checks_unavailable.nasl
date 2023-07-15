#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110695);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/06");

  script_xref(name:"IAVB", value:"0001-B-0521");

  script_name(english:"OS Security Patch Assessment Checks Not Supported");
  script_summary(english:"Displays information about the scan");

  script_set_attribute(attribute:"synopsis", value:"OS Security Patch Assessment is not supported for the target.");
  script_set_attribute(attribute:"description", value:
"OS Security Patch Assessment is not available for this host because
the checks may be infeasible or are not supported by Nessus. The
credentials supplied in the scan policy may have been successful, but
OS Security Patch Assessment cannot be performed at this time.");
  script_set_attribute(attribute:"solution", value:
"If OS Security Patch Assessment is required for this host, contact Tenable
support.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_END);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Settings");

  # No dependencies, since this is an ACT_END plugin
  script_require_keys("HostLevelChecks/unavailable");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("lcx.inc");

scripts = get_kb_list_or_exit("HostLevelChecks/unavailable"); 

if (lcx::get_issue_count(type:lcx::ISSUES_ERROR) > 0)
{
  exit(0, "OS Security Patch Assessment is not available due to an error.");
}

if (!empty_or_null(get_kb_item("HostLevelChecks/local_security_checks_enabled")))
{
  exit(0, "OS Security Patch Assessment is available.");
}

var report, previous_report, previous_reports;

lcx::log_issue(type:lcx::ISSUES_INFO, msg:
  "OS Security Patch Assessment is not available.");
report =
  'A successful connection to the remote host was established, but OS\n' +
  'Security Patch Assessment is not available.\n';

previous_reports = make_list();
foreach script (scripts)
{
  previous_reports[max_index(previous_reports)] =
    lcx::get_reports(plugin:script);
}

info = "";
foreach plugin_reports (previous_reports)
{
  foreach previous_report (plugin_reports)
  {
    report +=
      '\nPlugin      : ' + previous_report['plugin'];
    if (previous_report['plugin_id']) report +=
      '\nPlugin ID   : ' + previous_report['plugin_id'];
    if (previous_report['plugin_name']) report +=
      '\nPlugin Name : ' + previous_report['plugin_name'];
    report +=
      '\nReport      :' +
      '\n====================' +
      '\n' + previous_report['text'] +
      '\n====================\n';
  }
}
if (info)
  report += '\nSee the following report(s) for the reason :\n' + info;

security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
