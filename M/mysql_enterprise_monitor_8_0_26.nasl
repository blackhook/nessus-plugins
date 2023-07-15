##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163293);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2021-22119");
  script_xref(name:"IAVA", value:"2022-A-0291");

  script_name(english:"Oracle MySQL Enterprise Monitor DOS (July 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by DOS");
  script_set_attribute(attribute:"description", value:
"The version of MySQL Enterprise Monitor installed on the remote host are affected by a denial of service as
referenced in the July 2022 CPU advisory, via the initiation of the Authorization Request in an OAuth 2.0 Client
 Web and WebFlux application. A malicious user or attacker can send multiple requests initiating the Authorization 
 Request for the Authorization Code Grant, which has the potential of exhausting system resources using a single 
 session or multiple sessions.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22119");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_enterprise_monitor");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_enterprise_monitor_web_detect.nasl", "oracle_mysql_enterprise_monitor_local_nix_detect.nbin", "oracle_mysql_enterprise_monitor_local_detect.nbin", "macosx_mysql_enterprise_monitor_installed.nbin");
  script_require_keys("installed_sw/MySQL Enterprise Monitor");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'MySQL Enterprise Monitor');

var constraints = [
  { 'min_version' : '8.0', 'fixed_version' : '8.0.26' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);