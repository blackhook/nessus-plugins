#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102079);
  script_version ("1.3");
  script_cvs_date("Date: 2018/07/12 19:01:16");

  script_cve_id(
    "CVE-2012-3365",
    "CVE-2013-4113",
    "CVE-2013-6420",
    "CVE-2014-9425"
  );
  script_bugtraq_id(
    54612,
    61128,
    64225,
    71800
  );
  script_xref(name:"JSA", value:"JSA10804");
  script_xref(name:"EDB-ID", value:"30395");

  script_name(english:"Juniper Junos PHP multiple vulnerabilities (JSA10804)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by multiple vulnerabilities in
the included PHP version :

  - An unspecified flaw exists in the SQLite extension
    that allows an unauthenticated, remote attacker to
    bypass the 'open_basedir' constraint. (CVE-2012-3365)

  - A heap-based buffer overflow condition exists in file
    ext/xml/xml.c due to not properly considering parsing
    depth. An unauthenticated, remote attacker can exploit
    this issue, via a specially crafted XML document that is
    processed by the xml_parse_into_struct() function, to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2013-4113)

  - A memory corruption issue exists in the PHP OpenSSL
    extension in the openssl_x509_parse() function due to
    improper sanitization of user-supplied input when
    parsing 'notBefore' and 'notAfter' timestamps in X.509
    certificates. An unauthenticated, remote attacker can
    exploit this issue, via a specially crafted certificate,
    to cause a denial of service condition or the execution
    of arbitrary code. (CVE-2013-6420)

  - A double-free error exists in the
    zend_ts_hash_graceful_destroy() function within file
    Zend/zend_ts_hash.c that allows an unauthenticated,
    remote attacker to cause a denial of service condition.
    (CVE-2014-9425)");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10804");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
security advisory JSA10804.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();

fixes['12.1X46'] = '12.1X46-D65';
fixes['12.1X47'] = '12.1X47-D40';
fixes['12.3R12'] = '12.3R12-S5';
fixes['12.3X48'] = '12.3X48-D35';
fixes['14.2']    = '14.2R8';
fixes['15.1']    = '15.1R4';
fixes['15.1X49'] = '15.1X49-D50';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for J-Web
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system services web-management http(s)? interface";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because J-Web is not enabled');

  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
