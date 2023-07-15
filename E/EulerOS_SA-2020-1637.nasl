#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137479);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2011-3210",
    "CVE-2011-4577",
    "CVE-2014-3470",
    "CVE-2014-3507",
    "CVE-2014-3511",
    "CVE-2014-3572",
    "CVE-2015-0205",
    "CVE-2015-0206",
    "CVE-2016-2176",
    "CVE-2016-2179"
  );
  script_bugtraq_id(
    49471,
    51281,
    67898,
    69078,
    69079,
    71940,
    71941,
    71942
  );

  script_name(english:"EulerOS 2.0 SP2 : openssl098e (EulerOS-SA-2020-1637)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the openssl098e package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The DTLS implementation in OpenSSL before 1.1.0 does
    not properly restrict the lifetime of queue entries
    associated with unused out-of-order messages, which
    allows remote attackers to cause a denial of service
    (memory consumption) by maintaining many crafted DTLS
    sessions simultaneously, related to d1_lib.c,
    statem_dtls.c, statem_lib.c, and
    statem_srvr.c.(CVE-2016-2179)

  - OpenSSL before 0.9.8s and 1.x before 1.0.0f, when RFC
    3779 support is enabled, allows remote attackers to
    cause a denial of service (assertion failure) via an
    X.509 certificate containing certificate-extension data
    associated with (1) IP address blocks or (2) Autonomous
    System (AS) identifiers.(CVE-2011-4577)

  - Memory leak in the dtls1_buffer_record function in
    d1_pkt.c in OpenSSL 1.0.0 before 1.0.0p and 1.0.1
    before 1.0.1k allows remote attackers to cause a denial
    of service (memory consumption) by sending many
    duplicate records for the next epoch, leading to
    failure of replay detection.(CVE-2015-0206)

  - The ephemeral ECDH ciphersuite functionality in OpenSSL
    0.9.8 through 0.9.8r and 1.0.x before 1.0.0e does not
    ensure thread safety during processing of handshake
    messages from clients, which allows remote attackers to
    cause a denial of service (daemon crash) via
    out-of-order messages that violate the TLS
    protocol.(CVE-2011-3210)

  - The X509_NAME_oneline function in
    crypto/x509/x509_obj.c in OpenSSL before 1.0.1t and
    1.0.2 before 1.0.2h allows remote attackers to obtain
    sensitive information from process stack memory or
    cause a denial of service (buffer over-read) via
    crafted EBCDIC ASN.1 data.(CVE-2016-2176)

  - The ssl3_get_cert_verify function in s3_srvr.c in
    OpenSSL 1.0.0 before 1.0.0p and 1.0.1 before 1.0.1k
    accepts client authentication with a Diffie-Hellman
    (DH) certificate without requiring a CertificateVerify
    message, which allows remote attackers to obtain access
    without knowledge of a private key via crafted TLS
    Handshake Protocol traffic to a server that recognizes
    a Certification Authority with DH
    support.(CVE-2015-0205)

  - The ssl3_get_key_exchange function in s3_clnt.c in
    OpenSSL before 0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1
    before 1.0.1k allows remote SSL servers to conduct
    ECDHE-to-ECDH downgrade attacks and trigger a loss of
    forward secrecy by omitting the ServerKeyExchange
    message.(CVE-2014-3572)

  - Memory leak in d1_both.c in the DTLS implementation in
    OpenSSL 0.9.8 before 0.9.8zb, 1.0.0 before 1.0.0n, and
    1.0.1 before 1.0.1i allows remote attackers to cause a
    denial of service (memory consumption) via zero-length
    DTLS fragments that trigger improper handling of the
    return value of a certain insert
    function.(CVE-2014-3507)

  - The ssl23_get_client_hello function in s23_srvr.c in
    OpenSSL 1.0.1 before 1.0.1i allows man-in-the-middle
    attackers to force the use of TLS 1.0 by triggering
    ClientHello message fragmentation in communication
    between a client and server that both support later TLS
    versions, related to a 'protocol downgrade'
    issue.(CVE-2014-3511)

  - The ssl3_send_client_key_exchange function in s3_clnt.c
    in OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and
    1.0.1 before 1.0.1h, when an anonymous ECDH cipher
    suite is used, allows remote attackers to cause a
    denial of service (NULL pointer dereference and client
    crash) by triggering a NULL certificate
    value.(CVE-2014-3470)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1637
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27f046c9");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl098e packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl098e");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["openssl098e-0.9.8e-29.3.h21"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl098e");
}
