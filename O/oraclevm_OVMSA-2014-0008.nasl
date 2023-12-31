#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2014-0008.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79532);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2009-2409",
    "CVE-2009-3245",
    "CVE-2009-3555",
    "CVE-2009-4355",
    "CVE-2010-0433",
    "CVE-2010-4180",
    "CVE-2011-4108",
    "CVE-2011-4109",
    "CVE-2011-4576",
    "CVE-2011-4619",
    "CVE-2012-0050",
    "CVE-2012-0884",
    "CVE-2012-1165",
    "CVE-2012-2110",
    "CVE-2012-2333",
    "CVE-2012-4929",
    "CVE-2013-0166",
    "CVE-2013-0169",
    "CVE-2014-0224"
  );
  script_bugtraq_id(
    29330,
    31692,
    36935,
    38562,
    45164,
    51281,
    51563,
    52428,
    52764,
    53158,
    53476,
    55704,
    57755,
    57778,
    60268,
    67899
  );
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"OracleVM 3.2 : onpenssl (OVMSA-2014-0008)");

  script_set_attribute(attribute:"synopsis", value:
"The remote OracleVM host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - fix for CVE-2014-0224 - SSL/TLS MITM vulnerability

  - replace expired GlobalSign Root CA certificate in
    ca-bundle.crt

  - fix for CVE-2013-0169 - SSL/TLS CBC timing attack
    (#907589)

  - fix for CVE-2013-0166 - DoS in OCSP signatures checking
    (#908052)

  - enable compression only if explicitly asked for or
    OPENSSL_DEFAULT_ZLIB environment variable is set (fixes
    CVE-2012-4929 #857051)

  - use __secure_getenv everywhere instead of getenv
    (#839735)

  - fix for CVE-2012-2333 - improper checking for record
    length in DTLS (#820686)

  - fix for CVE-2012-2110 - memory corruption in
    asn1_d2i_read_bio (#814185)

  - fix problem with the SGC restart patch that might
    terminate handshake incorrectly

  - fix for CVE-2012-0884 - MMA weakness in CMS and PKCS#7
    code (#802725)

  - fix for CVE-2012-1165 - NULL read dereference on bad
    MIME headers (#802489)

  - fix for CVE-2011-4108 & CVE-2012-0050 - DTLS plaintext
    recovery vulnerability and additional DTLS fixes
    (#771770)

  - fix for CVE-2011-4109 - double free in policy checks
    (#771771)

  - fix for CVE-2011-4576 - uninitialized SSL 3.0 padding
    (#771775)

  - fix for CVE-2011-4619 - SGC restart DoS attack (#771780)

  - add known answer test for SHA2 algorithms (#740866)

  - make default private key length in certificate Makefile
    2048 bits (can be changed with PRIVATE_KEY_BITS setting)
    (#745410)

  - fix incorrect return value in parse_yesno (#726593)

  - added DigiCert CA certificates to ca-bundle (#735819)

  - added a new section about error states to README.FIPS
    (#628976)

  - add missing DH_check_pub_key call when DH key is
    computed (#698175)

  - presort list of ciphers available in SSL (#688901)

  - accept connection in s_server even if getaddrinfo fails
    (#561260)

  - point to openssl dgst for list of supported digests
    (#608639)

  - fix handling of future TLS versions (#599112)

  - added VeriSign Class 3 Public Primary Certification
    Authority - G5 and StartCom Certification Authority
    certs to ca-bundle (#675671, #617856)

  - upstream fixes for the CHIL engine (#622003, #671484)

  - add SHA-2 hashes in SSL_library_init (#676384)

  - fix CVE-2010-4180 - completely disable code for
    SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG (#659462)

  - fix CVE-2009-3245 - add missing bn_wexpand return checks
    (#570924)

  - fix CVE-2010-0433 - do not pass NULL princ to
    krb5_kt_get_entry which in the RHEL-5 and newer versions
    will crash in such case (#569774)

  - fix CVE-2009-3555 - support the safe renegotiation
    extension and do not allow legacy renegotiation on the
    server by default (#533125)

  - fix CVE-2009-2409 - drop MD2 algorithm from EVP tables
    (#510197)

  - fix CVE-2009-4355 - do not leak memory when
    CRYPTO_cleanup_all_ex_data is called prematurely by
    application (#546707)");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/oraclevm-errata/2014-June/000208.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 310, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"OracleVM Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "3\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.2", reference:"openssl-0.9.8e-27.el5_10.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl");
}
