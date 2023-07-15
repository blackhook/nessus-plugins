#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122536);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2014-9767",
    "CVE-2015-8867",
    "CVE-2015-8874",
    "CVE-2015-8879"
  );
  script_bugtraq_id(
    76652,
    87481,
    90714,
    90842
  );

  script_name(english:"PHP 7.0.x < 7.0.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by 
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 7.x prior to 7.0.0. It is, therefore, affected by the
following vulnerabilities:

  - A directory traversal vulnerability in the
    ZipArchive::extractTo function of ext/zip/php_zip.c
    script. An unauthenticated, remote attacker can exploit
    this, by sending a crafted ZIP archive with empty
    directories, to disclose the contents of files located
    outside of the server's restricted path. (CVE-2014-9767)

  - The openssl_random_pseudo_bytes() function in file
    openssl.c does not generate sufficiently random numbers.
    This allows an attacker to more easily predict the
    results, thus allowing further attacks to be carried
    out. (CVE-2015-8867)

  - A denial of service (DoS) vulnerability exists in the GD
    graphics library in the gdImageFillToBorder() function
    within file gd.c when handling crafted images that have
    an overly large negative coordinate. An unauthenticated,
    remote attacker can exploit this, via a crafted image,
    to crash processes linked against the library.
    (CVE-2015-8874)

  - A denial of service (DoS) vulnerability exists in
    odbc_bindcols function of the ext/odbc/php_odbc.c script
    due to mishandling driver behavior for SQL_WVARCHAR
    columns. An unauthenticated, remote attacker can exploit
    this issue, via the use of odbc_fetch_array function, to
    cause the application to stop responding. (CVE-2015-8879)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.0.0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8867");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/03");
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
  { "min_version" : "7.0.0alpha0", "fixed_version" : "7.0.0" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
