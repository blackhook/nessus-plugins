#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101527);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2017-7890",
    "CVE-2017-9224",
    "CVE-2017-9226",
    "CVE-2017-9227",
    "CVE-2017-9228",
    "CVE-2017-9229",
    "CVE-2017-11144",
    "CVE-2017-11145",
    "CVE-2017-11362",
    "CVE-2017-11628",
    "CVE-2017-12933",
    "CVE-2017-12934"
  );
  script_bugtraq_id(
    99489,
    99490,
    99492,
    99501,
    100428
  );

  script_name(english:"PHP 7.1.x < 7.1.7 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 7.1.x prior to 7.1.7. It is, therefore, affected by the
following vulnerabilities :

  - An out-of-bounds read error exists in the GD Graphics
    Library (LibGD) in the gdImageCreateFromGifCtx()
    function within file gd_gif_in.c when handling a
    specially crafted GIF file. An unauthenticated, remote
    attacker can exploit this to disclose sensitive memory
    contents or crash a process linked to the library.
    (CVE-2017-7890)

  - An out-of-bounds read error exists in Oniguruma in the
    match_at() function within file regexec.c. An
    unauthenticated, remote attacker can exploit this to
    disclose sensitive memory contents or crash a process
    linked to the library. (CVE-2017-9224)

  - An out-of-bounds write error exists in Oniguruma in the
    next_state_val() function during regular expression
    compilation. An unauthenticated, remote attacker can
    exploit this to execute arbitrary code. (CVE-2017-9226)

  - An out-of-bounds read error exists in Oniguruma in the
    mbc_enc_len() function within file utf8.c. An
    unauthenticated, remote attacker can exploit this to
    disclose memory contents or crash a process linked to
    the library. (CVE-2017-9227)

  - An out-of-bounds write error exists in Oniguruma in the
    bitset_set_range() function during regular expression
    compilation. An unauthenticated, remote attacker can
    exploit this to execute arbitrary code. (CVE-2017-9228)

  - An invalid pointer deference flaw exists in Oniguruma
    in the left_adjust_char_head() function within file
    regexec.c during regular expression compilation. An
    unauthenticated, remote attacker can exploit this to
    crash a process linked to the library, resulting in a
    denial of service condition. (CVE-2017-9229)

  - A flaw exists in OpenSSL in the EVP_SealInit() function
    within file crypto/evp/p_seal.c due to returning an
    undocumented value of '-1'. An unauthenticated, remote
    attacker can exploit this to cause an unspecified
    impact. (CVE-2017-11144)

  - An out-of-bounds read error exists in PHP in the
    php_parse_date() function within file
    ext/date/lib/parse_date.c. An unauthenticated, remote
    attacker can exploit this to disclose memory contents or
    cause a denial of service condition. (CVE-2017-11145)

  - A stack-based buffer overflow condition exists in PHP
    in the msgfmt_parse_message() function due to improper
    validation of user-supplied input when parsing locale.
    An unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2017-11362)

  - An off-by-one overflow condition exists in PHP in the
    INI parsing API, specifically in the zend_ini_do_op()
    function within file Zend/zend_ini_parser.c, due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2017-11628)

  - An out-of-bounds read error exists in PHP in the
    finish_nested_data() function within file
    ext/standard/var_unserializer.re. An unauthenticated,
    remote attacker can exploit this to disclose memory
    contents or cause a denial of service condition.
    (CVE-2017-12933)

  - A use-after-free error exists in PHP in the
    zval_get_type() function within file
    ext/standard/var_unserializer.c. An unauthenticated,
    remote attacker can exploit this to execute arbitrary
    code. (CVE-2017-12934)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.1.7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.1.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12933");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");

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
  { "min_version" : "7.1.0alpha0", "fixed_version" : "7.1.7" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
