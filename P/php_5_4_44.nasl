#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85298);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2015-6831",
    "CVE-2015-6832",
    "CVE-2015-6833",
    "CVE-2015-8867"
  );
  script_bugtraq_id(
    76735,
    76737,
    76739,
    87481
  );

  script_name(english:"PHP 5.4.x < 5.4.44 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 5.4.x prior to 5.4.44. It is, therefore, affected by
multiple vulnerabilities:

  - Multiple use-after-free vulnerabilities exist in the SPL
    component, due to improper handling of a specially 
    crafted serialized object. An unauthenticated, remote
    attack can exploit this, via vectors involving
    ArrayObject, splObjectStorage and SplDoublyLinkedList to
    execute arbitrary code. (CVE-2015-6831)

  - A use-after-free vulnerability exists in
    ext/spl/spl_array.c due to improper handling of a
    specially crafted serialized data. An unauthenticated,
    remote attacker can exploit this via specially crafted
    serialized data that triggers misuse of an array field
    to execute arbitrary code. (CVE-2015-6832)

  - A directory traversal vulnerability exists in the
    PharData class, due to improper implementation of the
    exctractTo function. An unauthenticated, remote attacker
    can exploit this via a crafted ZIP archive entry to
    write to arbitrary files. (CVE-2015-6833)

  - The openssl_random_pseudo_bytes() function in file
    openssl.c does not generate sufficiently random numbers.
    An unauthenticated, remote attacker can exploit this to
    defeat cryptographic protection mechanisms.
    (CVE-2015-8867)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://php.net/ChangeLog-5.php#5.4.44
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24db51f6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.4.44 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6832");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

fix = '5.4.44';
minver = '5.4.0alpha1';

regexes = make_array(
  -3, 'alpha(\\d+)',
  -2, 'beta(\\d+)',
  -1, 'RC(\\d+)'
);

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

ver = php["ver"];
source = php["src"];
backported = get_kb_item('www/php/' + port + '/' + ver + '/backported');

if ((report_paranoia < 2) && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, 'PHP ' + ver + ' install');

vulnerable = ver_compare(minver:minver, ver:ver, fix:fix, regexes:regexes);
if (isnull(vulnerable)) exit(1, 'The version of PHP ' + ver + ' is not within the checked ranges.');
if (vulnerable > -1) audit(AUDIT_LISTEN_NOT_VULN, 'PHP', port, ver);

report =
'\n  Version source    : ' + source +
'\n  Installed version : ' + ver +
'\n  Fixed version     : ' + fix +
'\n';
security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
