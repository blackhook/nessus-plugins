#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101048);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id(
    "CVE-2016-7411",
    "CVE-2016-7412",
    "CVE-2016-7413",
    "CVE-2016-7414",
    "CVE-2016-7416",
    "CVE-2016-7417",
    "CVE-2016-7418"
  );
  script_bugtraq_id(
    93004,
    93005,
    93006,
    93007,
    93008,
    93009,
    93011
  );

  script_name(english:"Tenable SecurityCenter PHP < 5.6.26 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PHP in SecurityCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The Tenable SecurityCenter application on the remote host contains a
PHP library that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Tenable SecurityCenter application installed on the remote host
is missing a security patch. It is, therefore, affected by multiple
vulnerabilities in the bundled version of PHP :

  - A flaw exists in ext/standard/var_unserializer.re when
    destroying deserialized objects due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this, via a deserialize
    call that references a partially constructed object, to
    corrupt memory, resulting in a denial of service
    condition. (CVE-2016-7411)

  - An heap buffer overflow condition exists in the
    php_mysqlnd_rowp_read_text_protocol_aux() function
    within file ext/mysqlnd/mysqlnd_wireprotocol.c due to
    a failure to verify that a BIT field has the
    UNSIGNED_FLAG flag. An unauthenticated, remote attacker
    can exploit this, via specially crafted field metadata,
    to cause a denial of service condition. (CVE-2016-7412)

  - A use-after-free error exists in the
    wddx_stack_destroy() function within file
    ext/wddx/wddx.c when deserializing recordset elements.
    An unauthenticated, remote attacker can exploit this,
    via a specially crafted wddxPacket XML document, to
    cause a denial of service condition. (CVE-2016-7413)

  - An out-of-bounds access error exists in the
    phar_parse_zipfile() function within file ext/phar/zip.c
    due to a failure to ensure that the
    uncompressed_filesize field is large enough. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted archive, to cause a denial of service
    condition. (CVE-2016-7414)

  - A stack-based buffer overflow condition exists in the
    ICU4C library, specifically within file common/locid.cpp
    in the msgfmt_format_message() function, due to a
    failure to properly restrict the locale length provided
    to the Locale class. An unauthenticated, remote attacker
    can exploit this, via a long first argument to a
    MessageFormatter::formatMessage() function call, to
    cause a denial of service condition. (CVE-2016-7416)

  - A flaw exists in the spl_array_get_dimension_ptr_ptr()
    function within file ext/spl/spl_array.c due to a
    failure to properly validate the return value and data
    type when deserializing SplArray. An unauthenticated,
    remote attacker can exploit this, via specially crafted
    serialized data, to cause a denial of service condition.
    (CVE-2016-7417)

  - An out-of-bounds read error exists in the
    php_wddx_push_element() function within file
    ext/wddx/wddx.c when handling an incorrect boolean
    element, which leads to mishandling the
    wddx_deserialize() call. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    wddxPacket XML document, to cause a denial of service
    condition. (CVE-2016-7418)

  - An out-of-bounds access error exists in the
    phar_parse_tarfile() function within file ext/phar/tar.c
    when handling the verification of signatures. An
    unauthenticated, remote attacker can exploit this to
    cause an unspecified impact.

  - An integer overflow condition exists in the fgetcsv()
    function when handling CSV field lengths due to improper
    validation of certain input. An unauthenticated, remote
    attacker can exploit this to corrupt memory, resulting
    in a denial of service condition or the execution of
    arbitrary code.

  - An integer overflow condition exists in the wordwrap()
    function within file ext/standard/string.c due to
    improper validation of certain input. An
    unauthenticated, remote attacker can exploit this to
    corrupt memory, resulting in a denial of service
    condition or the execution of arbitrary code.

  - An integer overflow condition exists in the fgets()
    function within file ext/standard/file.c due to improper
    validation of certain input. An unauthenticated, remote
    attacker can exploit this to corrupt memory, resulting
    in a denial of service condition or the execution of
    arbitrary code.

  - An integer overflow condition exists in the
    xml_utf8_encode() function within file ext/xml/xml.c due
    to improper validation of certain input. An
    unauthenticated, remote attacker can exploit this to
    cause an unspecified impact.

  - A flaw exists in the exif_process_IFD_in_TIFF() function
    within file ext/exif/exif.c when handling uninitialized
    thumbnail data. An unauthenticated, remote attacker can
    exploit this to disclose memory contents.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.6.26");
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
  

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/13");
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
fix = "5.6.26";

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
