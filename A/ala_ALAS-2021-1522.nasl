#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2021-1522.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151520);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/13");

  script_cve_id(
    "CVE-2019-11719",
    "CVE-2019-11727",
    "CVE-2019-11756",
    "CVE-2019-17006",
    "CVE-2019-17023",
    "CVE-2020-6829",
    "CVE-2020-12400",
    "CVE-2020-12401",
    "CVE-2020-12402",
    "CVE-2020-12403"
  );
  script_xref(name:"IAVA", value:"2019-A-0231-S");
  script_xref(name:"IAVA", value:"2019-A-0438-S");
  script_xref(name:"IAVA", value:"2020-A-0002-S");
  script_xref(name:"IAVA", value:"2020-A-0391-S");
  script_xref(name:"IAVA", value:"2020-A-0287-S");
  script_xref(name:"ALAS", value:"2021-1522");

  script_name(english:"Amazon Linux AMI : nspr, nss-softokn, nss-util (ALAS-2021-1522)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of nspr installed on the remote host is prior to 4.25.0-2.45. The version of nss-softokn installed on the
remote host is prior to 3.53.1-6.46. The version of nss-util installed on the remote host is prior to 3.53.1-1.58. It
is, therefore, affected by multiple vulnerabilities as referenced in the ALAS-2021-1522 advisory.

  - When importing a curve25519 private key in PKCS#8format with leading 0x00 bytes, it is possible to trigger
    an out-of-bounds read in the Network Security Services (NSS) library. This could lead to information
    disclosure. This vulnerability affects Firefox ESR < 60.8, Firefox < 68, and Thunderbird < 60.8.
    (CVE-2019-11719)

  - A vulnerability exists where it possible to force Network Security Services (NSS) to sign
    CertificateVerify with PKCS#1 v1.5 signatures when those are the only ones advertised by server in
    CertificateRequest in TLS 1.3. PKCS#1 v1.5 signatures should not be used for TLS 1.3 messages. This
    vulnerability affects Firefox < 68. (CVE-2019-11727)

  - Improper refcounting of soft token session objects could cause a use-after-free and crash (likely limited
    to a denial of service). This vulnerability affects Firefox < 71. (CVE-2019-11756)

  - In Network Security Services (NSS) before 3.46, several cryptographic primitives had missing length
    checks. In cases where the application calling the library did not perform a sanity check on the inputs it
    could result in a crash due to a buffer overflow. (CVE-2019-17006)

  - After a HelloRetryRequest has been sent, the client may negotiate a lower protocol that TLS 1.3, resulting
    in an invalid state transition in the TLS State Machine. If the client gets into this state, incoming
    Application Data records will be ignored. This vulnerability affects Firefox < 72. (CVE-2019-17023)

  - When converting coordinates from projective to affine, the modular inversion was not performed in constant
    time, resulting in a possible timing-based side channel attack. This vulnerability affects Firefox < 80
    and Firefox for Android < 80. (CVE-2020-12400)

  - During ECDSA signature generation, padding applied in the nonce designed to ensure constant-time scalar
    multiplication was removed, resulting in variable-time execution dependent on secret data. This
    vulnerability affects Firefox < 80 and Firefox for Android < 80. (CVE-2020-12401)

  - During RSA key generation, bignum implementations used a variation of the Binary Extended Euclidean
    Algorithm which entailed significantly input-dependent flow. This allowed an attacker able to perform
    electromagnetic-based side channel attacks to record traces leading to the recovery of the secret primes.
    *Note:* An unmodified Firefox browser does not generate RSA keys in normal operation and is not affected,
    but products built on top of it might. This vulnerability affects Firefox < 78. (CVE-2020-12402)

  - A flaw was found in the way CHACHA20-POLY1305 was implemented in NSS in versions before 3.55. When using
    multi-part Chacha20, it could cause out-of-bounds reads. This issue was fixed by explicitly disabling
    multi-part ChaCha20 (which was not functioning correctly) and strictly enforcing tag length. The highest
    threat from this vulnerability is to confidentiality and system availability. (CVE-2020-12403)

  - When performing EC scalar point multiplication, the wNAF point multiplication algorithm was used; which
    leaked partial information about the nonce used during signature generation. Given an electro-magnetic
    trace of a few signature generations, the private key could have been computed. This vulnerability affects
    Firefox < 80 and Firefox for Android < 80. (CVE-2020-6829)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2021-1522.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11719");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11727");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11756");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-17006");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-17023");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12400");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12401");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12402");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12403");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6829");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update nspr' to update your system.
 Run 'yum update nss-softokn' to update your system.
 Run 'yum update nss-util' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17006");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nspr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-softokn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-softokn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-softokn-freebl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-softokn-freebl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

pkgs = [
    {'reference':'nspr-4.25.0-2.45.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nspr-4.25.0-2.45.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nspr-debuginfo-4.25.0-2.45.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nspr-debuginfo-4.25.0-2.45.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nspr-devel-4.25.0-2.45.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nspr-devel-4.25.0-2.45.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-3.53.1-6.46.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-3.53.1-6.46.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-debuginfo-3.53.1-6.46.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-debuginfo-3.53.1-6.46.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-devel-3.53.1-6.46.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-devel-3.53.1-6.46.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-freebl-3.53.1-6.46.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-freebl-3.53.1-6.46.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-freebl-devel-3.53.1-6.46.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-freebl-devel-3.53.1-6.46.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-util-3.53.1-1.58.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-util-3.53.1-1.58.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-util-debuginfo-3.53.1-1.58.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-util-debuginfo-3.53.1-1.58.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-util-devel-3.53.1-1.58.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-util-devel-3.53.1-1.58.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr / nspr-debuginfo / nspr-devel / etc");
}