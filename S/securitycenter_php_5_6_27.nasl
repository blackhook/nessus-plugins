#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101049);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id(
    "CVE-2016-9137"
  );
  script_bugtraq_id(
    93577
  );

  script_name(english:"Tenable SecurityCenter PHP < 5.6.27 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PHP in SecurityCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The Tenable SecurityCenter application on the remote host contains a
PHP library that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Tenable SecurityCenter application installed on the remote host
is missing a security patch. It is, therefore, affected by multiple
vulnerabilities in the bundled version of PHP :

  - A use-after-free error exists in the unserialize()
    function that allows an unauthenticated, remote attacker
    to dereference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2016-9137)

  - A NULL pointer dereference flaw exists in the
    SimpleXMLElement::asXML() function within file
    ext/simplexml/simplexml.c. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition.

  - A heap-based buffer overflow condition exists in the
    php_ereg_replace() function within file ext/ereg/ereg.c
    due to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code.

  - A flaw exists in the openssl_random_pseudo_bytes()
    function within file ext/openssl/openssl.c when handling
    strings larger than 2GB. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition.

  - A flaw exists in the openssl_encrypt() function within
    file ext/openssl/openssl.c when handling strings larger
    than 2GB. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition.

  - An integer overflow condition exists in the
    imap_8bit() function within file ext/imap/php_imap.c due
    to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code.

  - A flaw exists in the _bc_new_num_ex() function within
    file ext/bcmath/libbcmath/src/init.c when handling
    values passed via the 'scale' parameter. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition.

  - A flaw exists in the php_resolve_path() function within
    file main/fopen_wrappers.c when handling negative size
    values passed via the 'filename' parameter. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition.

  - A flaw exists in the dom_document_save_html() function
    within file ext/dom/document.c due to missing NULL
    checks. An unauthenticated, remote attacker can exploit
    this to cause a denial of service condition.

  - An integer overflow condition exists in the
    mb_encode_*() functions in file ext/mbstring/mbstring.c
    due to improper validation of the length of encoded
    data. An unauthenticated, remote attacker can exploit
    this to cause a denial of service condition or the
    execution of arbitrary code.

  - A NULL pointer dereference flaw exists in the
    CachingIterator() function within file
    ext/spl/spl_iterators.c when handling string
    conversions. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition.

  - An integer overflow condition exists in the
    number_format() function within file ext/standard/math.c
    when handling 'decimals' and 'dec_point' parameters that
    have values that are equal or close to 0x7fffffff. An
    unauthenticated, remote attacker can exploit this to
    cause a heap buffer overflow, resulting in a denial of
    service condition or the execution of arbitrary code.

  - A stack-based overflow condition exists in the
    ResourceBundle::create and ResourceBundle::getLocales
    methods and their respective functions within file
    ext/intl/resourcebundle/resourcebundle_class.c due to
    improper validation of input passed via the 'bundlename'
    parameter. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition or
    the execution or arbitrary code.

  - An integer overflow condition exists in the
    php_pcre_replace_impl() function within file
    ext/pcre/php_pcre.c due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this to cause a heap-based buffer overflow,
    resulting in a denial of service condition or the
    execution of arbitrary code.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.6.27");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SecurityCenter version 5.4.1 or later. Alternatively,
contact the vendor for a patch.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");


  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_keys("Host/SecurityCenter/Version", "installed_sw/SecurityCenter", "Host/SecurityCenter/support/php/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'PHP (within SecurityCenter)';
fix = "5.6.27";

sc_ver = get_kb_item("Host/SecurityCenter/Version");
port = 0;
if(empty_or_null(sc_ver))
{
  port = 443;
  install = get_single_install(app_name:"SecurityCenter", combined:TRUE, exit_if_unknown_ver:TRUE);
  sc_ver = install["version"];
}
if (empty_or_null(sc_ver)) audit(AUDIT_NOT_INST, "SecurityCenter");

version = get_kb_item("Host/SecurityCenter/support/php/version");
if (empty_or_null(version)) audit(AUDIT_UNKNOWN_APP_VER, app);

if (ver_compare(ver:version, minver:"5.6.0", fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  SecurityCenter version     : ' + sc_ver +
    '\n  SecurityCenter PHP version : ' + version +
    '\n  Fixed PHP version          : ' + fix +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, version);
