#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137079);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Dotnetnuke 7.0.x < 9.5.0 XSS");

  script_set_attribute(attribute:"synopsis", value:
"An ASP.NET application running on the remote web server is affected by a XSS vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Dotnetnuke running on the remote web server is 7.0.x prior to
9.5.0. It is, therefore, affected by a XSS vulnerability.

  - For websites with user registration enabled, it is
    possible for a user to craft a registration that would
    inject malicious content to their profile that could
    expose information using an XSS style exploit.
    Mitigating Factors Websites not allowing registration
    will be unaffected by this issue. Fix(es) for This Issue
    Users must upgrade DNN Platform to version 9.5.0 or
    later to be protected from this issue. Affected Versions
    DNN Platform version 7.0.0 through 9.4.4 (2020-04)

Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dotnetnuke version 9.5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19790");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/03");

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
  { 'min_version' : '7.0.0', 'max_version' : '9.4.4', 'fixed_version' : '9.5.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{'xss':TRUE});
