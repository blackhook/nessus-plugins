#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168325);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/02");

  script_cve_id("CVE-2022-43782");
  script_xref(name:"IAVA", value:"2022-A-0496");

  script_name(english:"Atlassian Crowd 3.x / 4.x < 4.4.4 / 5.x < 5.0.3 Security Bypass (CWD-5888)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Atlassian Crowd installed on the remote host is affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Crowd installed on the remote host is 3.x, 4.x prior to 4.4.4, or 5.x prior to 5.0.3. It is,
therefore, affected by a security bypass vulnerability due to security misconfiguration. An unauthenticated, remote
attacker can exploit this by authenticating as the crowd application via the security misconfiguration, and calling
privileged endpoints in Crowd's REST API under the {{usermanagement}} path.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CWD-5888");
  # https://confluence.atlassian.com/crowd/crowd-security-advisory-november-2022-1168866129.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?668e0122");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 4.4.4, 5.0.3, 5.1.0, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-43782");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:crowd");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("crowd_detect.nasl");
  script_require_keys("www/crowd");
  script_require_ports("Services/www", 8095);

  exit(0);
}

include('vcf.inc');

var app = 'crowd';

var app_info = vcf::combined_get_app_info(app:app);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var fix = '4.4.4 / 5.0.3 / 5.1.0';

var constraints = [
  { 'min_version' : '3.0.0', 'fixed_version' : '4.4.4', 'fixed_display' : fix },
  { 'min_version' : '5.0.0', 'fixed_version' : '5.0.3', 'fixed_display' : fix }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
