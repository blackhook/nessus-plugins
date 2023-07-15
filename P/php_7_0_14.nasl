#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(95875);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2016-9935", "CVE-2016-9936");
  script_bugtraq_id(94846, 94849);

  script_name(english:"PHP 7.0.x < 7.0.14 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 7.0.x prior to 7.0.14. It is, therefore, affected by the
following vulnerabilities:

  -  A remote code execution vulnerability due to a memory
     corruption issue in the php_wddx_push_element()
     function in ext/wddx/wddx.c that occurs when decoding
     empty boolean elements. An unauthenticated, remote
     attacker can exploit this to cause a denial of service
     condition or the execution of arbitrary code.
     (CVE-2016-9935)

  - A deserialization vulnerability exists in the
    ext/standard/var.c script. An unauthenticated, remote
    attacker can exploit this, via crafted serialized data,
    to the application to stop responding or execute
    arbitrary code on the target host. (CVE-2016-9936)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.0.14");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.0.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9935");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { "min_version" : "7.0.0alpha0", "fixed_version" : "7.0.14" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
