#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125477);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-11580");
  script_xref(name:"IAVA", value:"2020-A-0499-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");
  script_xref(name:"CEA-ID", value:"CEA-2019-0571");

  script_name(english:"Atlassian Crowd 2.1.x < 3.0.5 / 3.1.x < 3.1.6 / 3.2.x < 3.2.8 / 3.3.x < 3.3.5 / 3.4.x < 3.4.4 RCE Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The version of Atlassian Crowd installed on the remote host is affected
by an remote code execution (RCE) vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Crowd installed on the remote host is 2.1.x prior
to 3.0.5, 3.1.x prior to 3.1.6, 3.2.x prior to 3.2.8, 3.3.x prior to 3.3.5 
or 3.4.x prior to 3.4.4. It is, therefore, affected by a remote code execution
(RCE) vulnerability. An unauthenticated, remote attacker can exploit this, by
using pdkinstall development plugin, to install arbitrary plugins, which permits
remote code execution.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://confluence.atlassian.com/crowd/crowd-security-advisory-2019-05-22-970260700.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f66fbb1c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 3.0.5, 3.1.6, 3.2.8, 3.3.5, 3.4.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11580");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Atlassian Crowd pdkinstall Unauthenticated Plugin Upload RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:crowd");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("crowd_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/crowd");
  script_require_ports("Services/www", 8095);

  exit(0);
}

include("http.inc");
include("vcf.inc");

port = get_http_port(default:8095);

app = "crowd";

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "2.1.0", "fixed_version" : "3.0.5" },
  { "min_version" : "3.1.0", "fixed_version" : "3.1.6" },
  { "min_version" : "3.2.0", "fixed_version" : "3.2.8" },
  { "min_version" : "3.3.0", "fixed_version" : "3.3.5" },
  { "min_version" : "3.4.0", "fixed_version" : "3.4.4" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

