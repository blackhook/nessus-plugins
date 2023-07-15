#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122543);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-12932");
  script_bugtraq_id(100427);

  script_name(english:"PHP 7.1.x < 7.1.9 Heap-based Buffer Overflow Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by
a heap-based buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 7.1.x prior to 7.1.9. It is, therefore, affected by a
heap-based buffer overflow condition exists in the
ext/standard/var_unserializer.re script due to improper use of the
hash API for key deletion. An unauthenticated, remote attacker can
exploit this to cause a denial of service condition or the execution
of arbitrary code.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.1.9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.1.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12932");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

constraints = [
  { "min_version" : "7.1.0alpha0", "fixed_version" : "7.1.9" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
