##
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2022/01/20. Version check invalidated.
##

include('compat.inc');

if (description)
{
  script_id(140214);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/20");

  script_xref(name:"IAVB", value:"2020-B-0058-S");

  script_name(english:"Slack < 4.4.0 Remote Code Execution (Deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated due to server side fixes.

The version of the Slack Desktop installed on the remote host is prior to 4.4.0. It is, therefore, affected by a
Remote Code Execution vulnerability. With any in-app redirect - logic/open redirect, HTML or javascript injection, 
it is possible to execute arbitrary code within Slack desktop apps. 

Note that Nessus has not tested for these issues but has instead relied only on the application's reported version
number.");
  # https://portswigger.net/daily-swig/critical-vulnerability-in-slack-desktop-app-could-lead-to-remote-code-execution
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1005734a");
  script_set_attribute(attribute:"see_also", value:"https://hackerone.com/reports/783877");
  script_set_attribute(attribute:"see_also", value:"https://slack.engineering/the-app-sandbox/");
  script_set_attribute(attribute:"solution", value:
"n/a");

  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on a Remote Code Execution vulnerability.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:slack:slack");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("slack_win_installed.nbin", "macosx_slack_installed.nbin");
  script_require_ports("installed_sw/Slack");

  exit(0);
}
exit(0, 'This plugin has been depricated. No replacement.');
