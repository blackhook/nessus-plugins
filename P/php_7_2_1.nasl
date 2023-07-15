#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105774);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-5711", "CVE-2018-5712", "CVE-2018-14884");
  script_bugtraq_id(102742, 102743, 104968);

  script_name(english:"PHP 7.2.x < 7.2.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 7.2.x prior to 7.2.1. It is, therefore, affected by the
following vulnerabilities :

  - A denial of service (DoS) vulnerability exists in the
    imagecreatefromgif and imagecreatefromstring functions
    of the gd_gif_in.c script within GD Graphics Library
    (libgd) due to an integer signedness error. An
    unauthenticated, remote attacker can exploit this issue,
    via a crafted GIF file, to cause the applicaiton to stop
    responding. (CVE-2018-5711)

  - A cross-site scripting (XSS) vulnerability exists due to
    improper validation of .phar file before returning it to
    users. An unauthenticated, remote attacker can exploit
    this, by convincing a user to click a specially crafted
    URL, to execute arbitrary script code in a user's browser
    session. (CVE-2018-5712)

  - A denial of service (DoS) vulnerability exists in the
    ext/standard/http_fopen_wrapper.c script due to
    http_header_value possibly being a NULL value in an atoi
    call. An unauthenticated, remote attacker can exploit
    this issue, via a specifically crafted HTTP response, to
    cause the application to stop responding. (CVE-2018-14884)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.2.1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5712");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");
include("http.inc");
include("webapp_func.inc");

vcf::php::initialize();

port = get_http_port(default:80, php:TRUE);

app_info = vcf::php::get_app_info(port:port);

flags = [
  { "xss" : TRUE }
];

constraints = [
  { "min_version" : "7.2.0alpha0", "fixed_version" : "7.2.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:flags);
