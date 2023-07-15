#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(96800);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2015-2787",
    "CVE-2016-7479",
    "CVE-2016-10158",
    "CVE-2016-10159",
    "CVE-2016-10160",
    "CVE-2016-10161",
    "CVE-2016-10162",
    "CVE-2016-10167",
    "CVE-2016-10168",
    "CVE-2017-5340",
    "CVE-2017-11147"
  );
  script_bugtraq_id(
    73431,
    95151,
    95371,
    95668,
    95764,
    95768,
    95774,
    95783,
    95869,
    99607
  );

  script_name(english:"PHP 7.0.x < 7.0.15 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 7.0.x prior to 7.0.15. It is, therefore, affected by the
following vulnerabilities :

  - A remote code execution vulnerability exists due to a
    use-after-free error in the unserialize() function that
    is triggered when using DateInterval input. An
    unauthenticated, remote attacker can exploit this to
    dereference already freed memory, resulting in a denial
    of service condition or the execution of arbitrary code.
    (CVE-2015-2787)

  - A use-after-free error exists that is triggered when
    handling unserialized object properties. An 
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary code.
    (CVE-2016-7479)

  - An integer overflow condition exists in the
    _zend_hash_init() function in zend_hash.c due to
    improper validation of unserialized objects. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2017-5340)

  - A floating pointer exception flaw exists in the
    exif_convert_any_to_int() function in exif.c that is
    triggered when handling TIFF and JPEG image tags. An
    unauthenticated, remote attacker can exploit this to
    cause a crash, resulting in a denial of service
    condition. (CVE-2016-10158)

  - An integer overflow condition exists in the
    phar_parse_pharfile() function in phar.c due to improper
    validation when handling phar archives. An
    unauthenticated, remote attacker can exploit this to
    cause a crash, resulting in a denial of service
    condition. (CVE-2016-10159)

  - An off-by-one overflow condition exists in the
    phar_parse_pharfile() function in phar.c due to improper
    parsing of phar archives. An unauthenticated, remote
    attacker can exploit this to cause a crash, resulting in
    a denial of service condition. (CVE-2016-10160)

  - An out-of-bounds read error exists in the
    finish_nested_data() function in var_unserializer.c due
    to improper validation of unserialized data. An
    unauthenticated, remote attacker can exploit this to
    cause a crash, resulting in a denial of service
    condition or the disclosure of memory contents.
    (CVE-2016-10161)

  - A NULL pointer dereference flaw exists in the
    php_wddx_pop_element() function in wddx.c due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    cause a crash, resulting in a denial of service
    condition. (CVE-2016-10162)

  - An signed integer overflow condition exists in gd_io.c
    due to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    have an unspecified impact.

  - A type confusion flaw exists that is triggered during
    the deserialization of specially crafted GMP objects. An
    unauthenticated, remote attacker can exploit this to
    cause a crash, resulting in a denial of service
    condition.

  - A type confusion error exists that is triggered when
    deserializing ZVAL objects. An unauthenticated, remote
    attacker can exploit this to execute arbitrary code.

  - A denial of service vulnerability exists in the bundled
    GD Graphics Library (LibGD) in the
    gdImageCreateFromGd2Ctx() function in gd_gd2.c due to
    improper validation of images. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted image, to crash the process. (CVE-2016-10167)

  - An integer overflow condition exists in the gd_io.c
    script of the GD Graphics Library (libgd). An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2016-10168)

  - An out-of-bounds read error exists in the
    phar_parse_pharfile() function in phar.c due to improper
    parsing of phar archives. An unauthenticated, remote
    attacker can exploit this to cause a crash, resulting in
    a denial of service condition. (CVE-2017-11147)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.0.15");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.0.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5340");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { "min_version" : "7.0.0alpha0", "fixed_version" : "7.0.15" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
