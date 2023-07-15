#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91899);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2016-4473",
    "CVE-2016-5766",
    "CVE-2016-5767",
    "CVE-2016-5768",
    "CVE-2016-5769",
    "CVE-2016-5770",
    "CVE-2016-5771",
    "CVE-2016-5772",
    "CVE-2016-5773"
  );
  script_bugtraq_id(91395, 98999);

  script_name(english:"PHP 7.0.x < 7.0.8 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 7.0.x prior to 7.0.8. It is, therefore, affected by multiple
vulnerabilities :

  - An invalid free flaw exists in the phar_extract_file()
    function within file ext/phar/phar_object.c that allows
    an unauthenticated, remote attacker to have an
    unspecified impact. (CVE-2016-4473)

  - An integer overflow condition exists in the
    _gd2GetHeader() function in file ext/gd/libgd/gd_gd2.c
    due to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2016-5766)

  - An integer overflow condition exists in the
    gdImagePaletteToTrueColor() function within file
    ext/gd/libgd/gd.c due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this to cause a denial of service condition
    or the execution of arbitrary code. (CVE-2016-5767)

  - A double-free error exists in the
    _php_mb_regex_ereg_replace_exec() function within file
    ext/mbstring/php_mbregex.c when handling a failed
    callback execution. An unauthenticated, remote attacker
    can exploit this to execute arbitrary code.
    (CVE-2016-5768)

  - An integer overflow condition exists within file
    ext/mcrypt/mcrypt.c due to improper validation of
    user-supplied input when handling data values. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2016-5769)

  - An integer overflow condition exists within file
    ext/spl/spl_directory.c, triggered by an int/size_t
    type confusion error, that allows an unauthenticated,
    remote attacker to have an unspecified impact.
    (CVE-2016-5770)

  - A use-after-free error exists in the garbage collection
    algorithm within file ext/spl/spl_array.c. An
    unauthenticated, remote attacker can exploit this to
    dereference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2016-5771)

  - A double-free error exists in the
    php_wddx_process_data() function within file
    ext/wddx/wddx.c when handling specially crafted XML
    content. An unauthenticated, remote attacker
    can exploit this to execute arbitrary code.
    (CVE-2016-5772)

  - A use-after-free error exists in the garbage collection
    algorithm within file ext/zip/php_zip.c. An
    unauthenticated, remote attacker can exploit this to
    dereference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2016-5773)

  - An integer overflow condition exists in the
    json_decode() and json_utf8_to_utf16() functions within
    file ext/standard/php_smart_str.h due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this to cause a denial of
    service condition or the execution of arbitrary code.

  - An out-of-bounds read error exists in the
    pass2_no_dither() function within file
    ext/gd/libgd/gd_topal.c that allows an unauthenticated,
    remote attacker to cause a denial of service condition
    or disclose memory contents.

  - An integer overflow condition exists within file
    ext/standard/string.c when handling string lengths due
    to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    have an unspecified impact.

  - A NULL pointer dereference flaw exists in the
    _gdScaleVert() function within file
    ext/gd/libgd/gd_interpolation.c that is triggered when
    handling _gdContributionsCalc return values. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition.

  - An integer overflow condition exists in the nl2br()
    function within file ext/standard/string.c when handling
    new_length values due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this to have an unspecified impact.

  - An integer overflow condition exists in multiple
    functions within file ext/standard/string.c when
    handling string values due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this to have an unspecified impact.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.0.8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4473");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/01");

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
  { "min_version" : "7.0.0alpha0", "fixed_version" : "7.0.8" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
