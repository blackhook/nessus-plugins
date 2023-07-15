#TRUSTED 790d4a4eeeac27d8b48edb3fab623667ab2c82044d2e868fdf63663b73a60c80de9368032eb41e57a53ae99084cfb6be80cea7996adb189390730674cfe52b952cbf5e9b3b3f91bccdf9821f2bbfcedf1bf0fc63d013ecf7b09b0f59bbebb0770891848f0c79fdd7f9685ccaf8348762ef4aba86530a2ee35a39852c7fc5c8b11a8ec01c525425c98edd053c317fed80334ab8e00ea5ce71e4664bf3c0dd242f796db31bb4e3e0bbaa63c4f9d5f9928e2475db7ac74d61a32c41e614da2b12814ae23904ba4b68434fa59785430c0ccc43708b6e11356335ab00216a99a2ce35f6f6fa8b4644c9270b98ff4000f74cf6b37387fe8e64a741c019d6613a527c6835f1746efedd21b99e6c91cda5c30ad7b87b2fbd0c9a26c8b79d993a6a7fa874003ee5a1fc16f8080125414663b3a9ac878e28eaa6bc452ed3b5ba7c4df0d9faa6aec1b2174507ece917f83114da206907d73d8f6d54f37ee112a74f66ae3c55f1fda044ff11ccab7858b4a2731f486d881afa449c28f90df5710515146f0a305478f103956165bcede319790d2148150fa653ec030b691041eefc3a5b5eae553f79c0f8358017c612b3989234957bc756230ba1fd285f4e22e3170bb49ddec0fd18f7b8aed69bbacc48c8cae3be59f9e5186a338709844a2287a412604c8aaef844f3dc7ccf4f769d060cf0d443851307e8c0d9b4e3cd35138689b55df4b2b1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117886);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/12");

  script_xref(name:"IAVB", value:"0001-B-0515");

  script_name(english:"OS Security Patch Assessment Not Available");
  script_summary(english:"Reports hosts that did not complete OS Security Patch Assessment.");

  script_set_attribute(attribute:"synopsis", value:
"OS Security Patch Assessment is not available.");
  script_set_attribute(attribute:"description", value:
"OS Security Patch Assessment is not available on the remote host.
This does not necessarily indicate a problem with the scan.
Credentials may not have been provided, OS security patch assessment
may not be supported for the target, the target may not have been
identified, or another issue may have occurred that prevented OS
security patch assessment from being available. See plugin output for
details.

This plugin reports non-failure information impacting the availability
of OS Security Patch Assessment. Failure information is reported by
plugin 21745 : 'OS Security Patch Assessment failed'.  If a target
host is not supported for OS Security Patch Assessment, plugin
110695 : 'OS Security Patch Assessment Checks Not Supported' will
report concurrently with this plugin.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/02");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_END2);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("local_checks_enabled.nasl");
  script_exclude_keys("HostLevelChecks/local_security_checks_enabled");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("lcx.inc");

if (get_kb_item("HostLevelChecks/local_security_checks_enabled"))
  exit(0, "OS Security Patch Assessment is available.");

if (lcx::get_issue_count(type:lcx::ISSUES_INFO) < 1)
{
  if (lcx::svc_available()) exit(0, "No issue reports were found.");
  else exit(0, "No local checks ports or services were detected.");
}

# Check for logged local checks informational issues
issues = lcx::get_issues(type:lcx::ISSUES_INFO);

report = '\nThe following issues were reported :\n';
foreach issue (issues)
{
  report +=
    '\n  - Plugin      : ' + issue['plugin'];
  if (issue['plugin_id']) report +=
    '\n    Plugin ID   : ' + issue['plugin_id'];
  if (issue['plugin_name']) report +=
    '\n    Plugin Name : ' + issue['plugin_name'];
  if (issue['proto_name']) report +=
    '\n    Protocol    : ' + issue['proto_name'];
  report +=
    '\n    Message     : ';
  # If message is more than one line or would exceed 70 chars with
  # the label field, add a newline
  lines = split(issue['text']);
  if (max_index(lines) > 1 || strlen(lines[0]) > (70 - 18))
    report += '\n';
  report += issue['text'] + '\n';
}

security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
