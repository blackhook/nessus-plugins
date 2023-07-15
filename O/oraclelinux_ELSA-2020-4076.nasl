##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-4076.
##

include('compat.inc');

if (description)
{
  script_id(141312);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/27");

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
  script_bugtraq_id(109085, 109086);

  script_name(english:"Oracle Linux 7 : nss / and / nspr (ELSA-2020-4076)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-4076 advisory.

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

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://linux.oracle.com/errata/ELSA-2020-4076.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17006");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-softokn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-softokn-freebl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-softokn-freebl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-util-devel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

pkgs = [
    {'reference':'nspr-4.25.0-2.el7_9', 'cpu':'i686', 'release':'7'},
    {'reference':'nspr-4.25.0-2.el7_9', 'cpu':'x86_64', 'release':'7'},
    {'reference':'nspr-devel-4.25.0-2.el7_9', 'cpu':'i686', 'release':'7'},
    {'reference':'nspr-devel-4.25.0-2.el7_9', 'cpu':'x86_64', 'release':'7'},
    {'reference':'nss-3.53.1-3.el7_9', 'cpu':'i686', 'release':'7'},
    {'reference':'nss-3.53.1-3.el7_9', 'cpu':'x86_64', 'release':'7'},
    {'reference':'nss-devel-3.53.1-3.el7_9', 'cpu':'i686', 'release':'7'},
    {'reference':'nss-devel-3.53.1-3.el7_9', 'cpu':'x86_64', 'release':'7'},
    {'reference':'nss-pkcs11-devel-3.53.1-3.el7_9', 'cpu':'i686', 'release':'7'},
    {'reference':'nss-pkcs11-devel-3.53.1-3.el7_9', 'cpu':'x86_64', 'release':'7'},
    {'reference':'nss-softokn-3.53.1-6.0.1.el7_9', 'cpu':'i686', 'release':'7'},
    {'reference':'nss-softokn-3.53.1-6.0.1.el7_9', 'cpu':'x86_64', 'release':'7'},
    {'reference':'nss-softokn-devel-3.53.1-6.0.1.el7_9', 'cpu':'i686', 'release':'7'},
    {'reference':'nss-softokn-devel-3.53.1-6.0.1.el7_9', 'cpu':'x86_64', 'release':'7'},
    {'reference':'nss-softokn-freebl-3.53.1-6.0.1.el7_9', 'cpu':'i686', 'release':'7'},
    {'reference':'nss-softokn-freebl-3.53.1-6.0.1.el7_9', 'cpu':'x86_64', 'release':'7'},
    {'reference':'nss-softokn-freebl-devel-3.53.1-6.0.1.el7_9', 'cpu':'i686', 'release':'7'},
    {'reference':'nss-softokn-freebl-devel-3.53.1-6.0.1.el7_9', 'cpu':'x86_64', 'release':'7'},
    {'reference':'nss-sysinit-3.53.1-3.el7_9', 'cpu':'x86_64', 'release':'7'},
    {'reference':'nss-tools-3.53.1-3.el7_9', 'cpu':'x86_64', 'release':'7'},
    {'reference':'nss-util-3.53.1-1.el7_9', 'cpu':'i686', 'release':'7'},
    {'reference':'nss-util-3.53.1-1.el7_9', 'cpu':'x86_64', 'release':'7'},
    {'reference':'nss-util-devel-3.53.1-1.el7_9', 'cpu':'i686', 'release':'7'},
    {'reference':'nss-util-devel-3.53.1-1.el7_9', 'cpu':'x86_64', 'release':'7'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  rpm_prefix = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['rpm_prefix'])) rpm_prefix = package_array['rpm_prefix'];
  if (reference && release) {
    if (rpm_prefix) {
        if (rpm_exists(release:release, rpm:rpm_prefix) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nspr / nspr-devel / nss / etc');
}