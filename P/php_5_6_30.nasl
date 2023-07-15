#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(96799);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2016-10158",
    "CVE-2016-10159",
    "CVE-2016-10160",
    "CVE-2016-10161",
    "CVE-2016-10167",
    "CVE-2016-10168",
    "CVE-2017-11147"
  );
  script_bugtraq_id(
    95764,
    95768,
    95774,
    95783,
    95869,
    99607
  );

  script_name(english:"PHP 5.6.x < 5.6.30 Multiple DoS");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 5.6.x prior to 5.6.30. It is, therefore, affected by the
following vulnerabilities :

  - A seg fault when loading hostile phar could be used
    to crash the PHP interpreter or potentially disclose
    information due to a buffer over-read in the
    phar_parse_pharfile function in ext/phar/phar.c.
    (CVE-2017-11147)

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

  - An out-of-bounds read error exists in the
    phar_parse_pharfile() function in phar.c due to improper
    parsing of phar archives. An unauthenticated, remote
    attacker can exploit this to cause a crash, resulting in
    a denial of service condition.

  - A denial of service vulnerability exists in the bundled
    GD Graphics Library (LibGD) in the
    gdImageCreateFromGd2Ctx() function in gd_gd2.c due to
    improper validation of images. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted image, to crash the process.

  - The gdImageCreateFromGd2Ctx function in gd_gd2.c in the
    GD Graphics Library could allow a remote attacker to
    cause a denial of service via a crafted image file.
    (CVE-2016-10167)

  - An integer overflow in gd_io.c in the GD Graphics
    Library before could allow a remote attacker to have
    an unspecified impact on PHP. (CVE-2016-10168)

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.6.30");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.6.30 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-10160");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/13");
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

fix = "5.6.30";
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
