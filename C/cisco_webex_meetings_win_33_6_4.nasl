#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119888);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/07");

  script_cve_id("CVE-2018-15442");
  script_bugtraq_id(105734);

  script_name(english:"Cisco Webex Meetings Desktop App < 33.6.4 Command Injection Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application affected by a command
injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Webex Desktop App installed on the remote host
is prior to 33.6.4, and thus, is affected by a command injection 
vulnerability.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181024-webex-injection
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3d7e129");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Webex Desktop App 33.6.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15442");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'WebExec Authenticated User Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex_meetings");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_webex_meetings_win_installed.nbin");
  script_require_keys("installed_sw/Cisco Webex Meetings", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("vcf.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = "Cisco Webex Meetings";

app_info = vcf::get_app_info(app:app_name);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version": "1.0.0",  "fixed_version" : "33.6.4" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

