#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155731);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/26");

  script_cve_id("CVE-2021-29045");
  script_xref(name:"IAVA", value:"2021-A-0296-S");

  script_name(english:"Liferay Portal 7.3.2 < 7.3.6 XSS");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"Liferay Portal 7.3.2 prior to 7.3.6 is affected by a cross-site scripting (XSS) vulnerability in its redirect module 
component due to improper validation of user-supplied input before returning it to users. An unauthenticated, remote 
attacker can exploit this, by convincing a user to click a specially crafted URL, to execute arbitrary script code in
a user's browser session.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://portal.liferay.dev/learn/security/known-vulnerabilities/-/asset_publisher/HbL5mxmVrnXW/content/id/120743484
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef939fcb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Liferay Portal 7.3 CE GA7 (7.3.6).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29045");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:liferay:portal");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("liferay_detect.nasl");
  script_require_keys("installed_sw/liferay_portal");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include('http.inc');
include('vcf.inc');

var port = get_http_port(default:8080);
var app_info = vcf::get_app_info(app:'liferay_portal', webapp:TRUE, port:port);

var constraints = [{'min_version': '7.3.2', 'fixed_version': '7.3.6'}];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
