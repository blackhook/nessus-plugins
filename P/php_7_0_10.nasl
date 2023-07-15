#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93078);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2016-7124",
    "CVE-2016-7125",
    "CVE-2016-7126",
    "CVE-2016-7127",
    "CVE-2016-7128",
    "CVE-2016-7129",
    "CVE-2016-7130",
    "CVE-2016-7131",
    "CVE-2016-7132",
    "CVE-2016-7133",
    "CVE-2016-7134"
  );
  script_bugtraq_id(
    92552,
    92564,
    92755,
    92756,
    92757,
    92758,
    92764,
    92765,
    92766,
    92767,
    92768
  );

  script_name(english:"PHP 7.0.x < 7.0.10 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 7.0.x prior to 7.0.10. It is, therefore, affected by
multiple vulnerabilities :

  - An unspecified flaw exists in the object_common2()
    function in var_unserializer.c that occurs when handling
    objects during deserialization. An unauthenticated,
    remote attacker can exploit this to execute arbitrary
    code. (CVE-2016-7124)

  - An unspecified flaw exists in session.c that occurs
    when handling session names. An unauthenticated, remote
    attacker can exploit this to inject arbitrary data into
    sessions. (CVE-2016-7125)

  - An integer truncation flaw exists in the select_colors()
    function in gd_topal.c that is triggered when handling
    the number of colors. An unauthenticated, remote
    attacker can exploit to cause a heap-based buffer
    overflow, resulting in the execution of arbitrary code.
    (CVE-2016-7126)

  - An indexing flaw exists in the imagegammacorrect()
    function in gd.c that occurs when handling negative
    gamma values. An unauthenticated, remote attacker can
    exploit this to write a NULL to an arbitrary memory
    location, resulting in a denial of service condition or
    the execution of arbitrary code. (CVE-2016-7127)

  - A flaw exists in the exif_process_IFD_in_TIFF() function
    in exif.c that occurs when handling TIFF image content.
    An unauthenticated, remote attacker can exploit this to
    disclose memory contents. (CVE-2016-7128)

  - A flaw exists in the php_wddx_process_data() function in
    wddx.c that occurs when deserializing invalid dateTime
    values. An unauthenticated, remote attacker can exploit
    this to cause a denial of service condition.
    (CVE-2016-7129)

  - A NULL pointer dereference flaw exists in the
    php_wddx_pop_element() function in wddx.c that is
    triggered during the handling of Base64 binary values.
    An unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (CVE-2016-7130)

  - A NULL pointer dereference flaw exists in the
    php_wddx_deserialize_ex() function in wddx.c that occurs
    during the handling of invalid XML content. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (CVE-2016-7131)

  - An unspecified NULL pointer dereference flaw exists in
    the php_wddx_pop_element() function in wddx.c. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (CVE-2016-7132)

   - An integer overflow condition exists in the
     zend_mm_realloc_heap() function in zend_alloc.c due to
     improper validation of user-supplied input. An
     unauthenticated, remote attacker can exploit this to
     cause a buffer overflow, resulting in a denial of
     service condition or the execution of arbitrary code.
     (CVE-2016-7133)

  - An overflow condition exists in the curl_escape()
    function in interface.c due to improper handling of
    overly long strings. An unauthenticated, remote attacker
    can exploit this to cause a heap-based buffer overflow,
    resulting in a denial of service condition or the
    execution of arbitrary code. (CVE-2016-7134)");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.0.10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.0.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7134");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/23");

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
  { "min_version" : "7.0.0alpha0", "fixed_version" : "7.0.10" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
