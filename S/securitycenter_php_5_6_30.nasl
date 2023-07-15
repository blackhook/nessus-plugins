#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101050);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id(
    "CVE-2017-11147",
    "CVE-2016-10158",
    "CVE-2016-10159",
    "CVE-2016-10160",
    "CVE-2016-10161",
    "CVE-2016-10167",
    "CVE-2016-10168"
  );
  script_bugtraq_id(
    95764,
    95768,
    95774,
    95783,
    95869,
    99607
  );

  script_name(english:"Tenable SecurityCenter PHP < 5.6.30 Multiple Vulnerabilities (TNS-2017-04)");
  script_summary(english:"Checks the version of PHP in SecurityCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The Tenable SecurityCenter application on the remote host contains a
PHP library that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Tenable SecurityCenter application installed on the remote host
is missing a security patch. It is, therefore, affected by multiple
vulnerabilities in the bundled version of PHP :

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

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2017-04");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.6.30");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SecurityCenter version 5.4.3 or later. Alternatively,
contact the vendor for a patch.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-10160");
  
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/09");
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
fix = "5.6.30";

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
