#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(94956);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2016-7478", "CVE-2016-9933", "CVE-2016-9934");
  script_bugtraq_id(94845, 94865);

  script_name(english:"PHP 7.0.x < 7.0.13 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 7.0.x prior to 7.0.13. It is, therefore, affected by
multiple vulnerabilities :

  - A stack consumption condition exists in the
    gdImageFillToBorder function of the gd.c script within
    the GD Graphics Library (libgd). An unauthenticated,
    remote attacker can exploit this issue, via a crafted
    call to imagefilltoborder using a negative color value,
    to cause the application to stop responding.
    (CVE-2016-9933)

  - A denial of service (DoS) vulnerability exists in the
    ext/wddx/wddx.c script. An unauthenticated, remote
    attacker can exploit this issue, via crafted serialized
    data in a wddxPacket XML document, to cause the
    application to stop responding. (CVE-2016-9934)

  - A flaw exists in the parse_url() function due to
    returning the incorrect host. An unauthenticated, remote
    attacker can exploit this to have a multiple impacts
    depending on how the function is implemented, which can
    include bypassing authentication or conducting open
    redirection and server-side request forgery attacks.

  - An integer overflow condition exists in the
    _php_imap_mail() function in file ext/imap/php_imap.c
    when handling overly long strings. An unauthenticated,
    remote attacker can exploit this to cause a
    heap-based buffer overflow, resulting in a denial of
    service condition or the execution of arbitrary code.

  - An integer overflow condition exists in the
    gdImageAALine() function within file ext/gd/libgd/gd.c
    due to improper validation of line limit values. An
    unauthenticated, remote attacker can exploit this to
    cause an out-of-bounds memory read or write, resulting
    in a denial of service condition, the disclosure of
    memory contents, or the execution of arbitrary code.

Note that this software is reportedly affected by other
vulnerabilities as well that have not been fixed yet in version
7.0.13.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.0.13");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.0.13 or later.

Note that this software is reportedly affected by other
vulnerabilities as well. Patches for these have been committed to the
source code repository, but until they are incorporated into the next
release of the software, manually installing an updated snapshot is
the only known solution.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7478");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/18");

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
  { "min_version" : "7.0.0alpha0", "fixed_version" : "7.0.13" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
