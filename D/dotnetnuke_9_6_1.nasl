#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137365);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/07");

  script_name(english:"Dotnetnuke 5.0.x < 9.6.1 (09.06.01)");

  script_set_attribute(attribute:"synopsis", value:
"An ASP.NET application running on the remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Dotnetnuke running on the remote web server is 5.0.x prior to
9.6.1. It is, therefore, affected by a vulnerability.

  - The maintainers of jQuery published version 3.5.0 with a
    security fix included regarding HTML manipulation.
    Fix(es) for this Issue DNN Platform 9.6.0 was released
    with 3.5.0 included, and 9.6.1 was released with jQuery
    3.5.1 after they released an urgent update. It is
    recommended to upgrade to the newest DNN Version to take
    advantage of these fixes. It is not possible to update
    jQuery alone without an DNN version upgrade. Affected
    Versions DNN Platform version 5.0.0 through 9.6.0
    (2020-07)

Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.dnnsoftware.com/community/security/security-center");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dotnetnuke version 9.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"No CVE available for this vulnerability.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dotnetnuke:dotnetnuke");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dotnetnuke_detect.nasl");
  script_require_keys("installed_sw/DNN");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

app = 'DNN';

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, asp:TRUE);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '5.0.0', 'fixed_version' : '9.6.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
