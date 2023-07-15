#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(88680);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2016-1903", "CVE-2016-1904", "CVE-2016-5114");
  script_bugtraq_id(79916, 81296, 81808);

  script_name(english:"PHP 7.x < 7.0.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote host
is 7.x prior to 7.0.2. It is, therefore, affected by multiple
vulnerabilities :

  - An out-of-bounds read error exists in the
    gdImageRotateInterpolated() function in file
    gd_interpolation.c when handling background colors.
    A remote attacker can exploit this to disclose memory
    contents or crash the application. (CVE-2016-1903)

  - An integer overflow condition exists in file exec.c
    in the escapeshellarg() and escapeshellcmd() functions
    due to a failure to properly validate user-supplied
    string input. A remote attacker can exploit this to
    cause a heap-based overflow, resulting in a denial of
    service or the execution of arbitrary code.
    (CVE-2016-1904)

  - A use-after-free error exists in file wddx.c in the
    php_wddx_pop_element() function when handling WDDX
    packet deserialization. A remote attacker can exploit
    this, by dereferencing already freed memory, to execute
    arbitrary code.

  - A type confusion flaw exists in file xmlrpc-epi-php.c
    in the PHP_to_XMLRPC_worker() function. A remote
    attacker can exploit this to disclose memory contents,
    crash the application process, or have other impact.

  - A type confusion flaw exists in file wddx.c when
    handling WDDX packet deserialization. A remote attacker
    can exploit this to execute arbitrary code.

  - An unspecified flaw exists in file fpm_log.c in the
    fpm_log_write() function when handling very long
    HTTP requests. A local attacker can exploit this to
    obtain sensitive information, via access to the
    access log file. (CVE-2016-5114)

  - A flaw exists in file lsapilib.c when handling requests
    due to the LSAPI module failing to clear its secrets in
    child processes. A remote attacker can exploit this to
    gain access to memory contents, resulting in the
    disclosure of sensitive information.

  - A flaw exists in file lsapilib.c in the parseRequest()
    function due to a failure to properly sanitize input
    passed through multiple, unspecified parameters. A
    remote attacker can exploit this to cause a denial of
    service.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.0.2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1904");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/10");

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
  { "min_version" : "7.0.0alpha0", "fixed_version" : "7.0.2" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
