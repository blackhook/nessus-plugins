#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101047);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id(
    "CVE-2016-7124",
    "CVE-2016-7125",
    "CVE-2016-7126",
    "CVE-2016-7127",
    "CVE-2016-7128",
    "CVE-2016-7129",
    "CVE-2016-7130",
    "CVE-2016-7131",
    "CVE-2016-7132"
  );
  script_bugtraq_id(
    92552,
    92564,
    92755,
    92756,
    92757,
    92758,
    92764,
    92767,
    92768
  );

  script_name(english:"Tenable SecurityCenter PHP < 5.6.25 Multiple Vulnerabilities (TNS-2016-09)");
  script_summary(english:"Checks the version of PHP in SecurityCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The Tenable SecurityCenter application on the remote host contains a
PHP library that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Tenable SecurityCenter application installed on the remote host
is missing a security patch. It is, therefore, affected by multiple
vulnerabilities in the bundled version of PHP :

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
    cause a denial of service condition. CVE-2016-7132)

  - An integer overflow condition exists in the
    php_snmp_parse_oid() function in snmp.c. An
    unauthenticated, remote attacker can exploit this to
    cause a heap-based buffer overflow, resulting in the
    execution of arbitrary code.

  - An overflow condition exists in the sql_regcase()
    function in ereg.c due to improper handling of overly
    long strings. An unauthenticated, remote attacker
    can exploit this to corrupt memory, resulting in the
    execution of arbitrary code.

  - An integer overflow condition exists in the
    php_base64_encode() function in base64.c that occurs
    when handling overly long strings. An unauthenticated, 
    remote attacker can exploit this to execute arbitrary
    code.

  - An integer overflow condition exists in the
    php_quot_print_encode() function in quot_print.c that
    occurs when handling overly long strings. An
    unauthenticated, remote attacker can exploit this to
    cause a heap-based buffer overflow condition, resulting
    in the execution of arbitrary code.

  - A use-after-free error exists in the unserialize()
    function in var.c. An unauthenticated, remote attacker
    can exploit this to dereference already freed memory,
    resulting in the execution of arbitrary code.

  - A flaw exists in the php_ftp_fopen_connect() function in 
    ftp_fopen_wrapper.c that allows a man-in-the-middle
    attacker to silently downgrade to regular FTP even if a
    secure method has been requested.

  - An integer overflow condition exists in the
    php_url_encode() function in url.c that occurs when
    handling overly long strings. An unauthenticated, remote
    attacker can exploit this to corrupt memory, resulting
    in the execution of arbitrary code.

  - An integer overflow condition exists in the
    php_uuencode() function in uuencode.c. An
    unauthenticated, remote attacker can exploit this to
    corrupt memory, resulting in the execution of arbitrary
    code.

  - An integer overflow condition exists in the
    bzdecompress() function in bz2.c. An unauthenticated,
    remote attacker can exploit this to corrupt memory,
    resulting in the execution of arbitrary code.

  - An integer overflow condition exists in the
    curl_escape() function in interface.c that occurs when
    handling overly long escaped strings. An 
    unauthenticated, remote attacker can exploit this to
    corrupt memory, resulting in the execution of arbitrary
    code.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2016-19");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.6.25");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SecurityCenter version 5.4.1 or later. Alternatively,
contact the vendor for a patch.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7124");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/10");
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
fix = "5.6.25";

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
