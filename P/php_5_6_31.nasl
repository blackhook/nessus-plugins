#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101525);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2017-6004",
    "CVE-2017-7890",
    "CVE-2017-9224",
    "CVE-2017-9226",
    "CVE-2017-9227",
    "CVE-2017-9228",
    "CVE-2017-9229",
    "CVE-2017-11142",
    "CVE-2017-11143",
    "CVE-2017-11144",
    "CVE-2017-11145",
    "CVE-2017-11628",
    "CVE-2017-12933"
  );
  script_bugtraq_id(
    96295,
    99489,
    99490,
    99492,
    99501,
    99550,
    99553,
    99601,
    99605,
    100320,
    100538,
    101244
  );

  script_name(english:"PHP 5.6.x < 5.6.31 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 5.6.x prior to 5.6.31. It is, therefore, affected by the
following vulnerabilities :

  - An out-of-bounds read error exists in the PCRE library
    in the compile_bracket_matchingpath() function within
    file pcre_jit_compile.c. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    regular expression, to crash a process linked to the
    library, resulting in a denial of service condition.
    (CVE-2017-6004)

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

  - A denial of service condition exists in PHP when
    handling overlarge POST requests. An unauthenticated,
    remote attacker can exploit this to exhaust available
    CPU resources. (CVE-2017-11142)

  - An extended invalid free error exists in PHP in the
    php_wddx_push_element() function within file
    ext/wddx/wddx.c when parsing empty boolean tags.
    An unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (CVE-2017-11143)

  - A flaw exists in OpenSSL in the EVP_SealInit() function
    within file crypto/evp/p_seal.c due to returning an
    undocumented value of '-1'. An unauthenticated, remote
    attacker can exploit this to cause an unspecified
    impact. (CVE-2017-11144)

  - An out-of-bounds read error exists in PHP in the
    php_parse_date() function within file
    ext/date/lib/parse_date.c. An unauthenticated, remote
    attacker can exploit this to disclose memory contents or
    cause a denial of service condition.
    (CVE-2017-11145)

  - An out-of-bounds read error exists in PHP in the
    finish_nested_data() function within file
    ext/standard/var_unserializer.re. An unauthenticated,
    remote attacker can exploit this to disclose memory
    contents or cause a denial of service condition.

  - An off-by-one overflow condition exists in PHP in the
    INI parsing API, specifically in the zend_ini_do_op()
    function within file Zend/zend_ini_parser.y, due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code.

  - A Heap buffer overread flaw in finish_nested_data
    while unserializing untrusted data could lead to an
    unspecified impact on the integrity of PHP.
    (CVE-2017-12933)

  - A stack-based buffer overflow in the zend_ini_do_op()
    function in Zend/zend_ini_parser.c could cause a denial
    of service or potentially allow executing code.
    (CVE-2017-11628)

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.6.31");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.6.31 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9224");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/23");
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

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
source = php["src"];

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

# Check that it is the correct version of PHP
if (version =~ "^5(\.6)?$") audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^5\.6\.") audit(AUDIT_NOT_DETECT, "PHP version 5.6.x", port);

fix = "5.6.31";
if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Version source    : ' + source +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
