##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:4076 and
# CentOS Errata and Security Advisory 2020:4076 respectively.
##

include('compat.inc');

if (description)
{
  script_id(142600);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/30");

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
  script_xref(name:"RHSA", value:"2020:4076");

  script_name(english:"CentOS 7 : nss and nspr (CESA-2020:4076)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:4076 advisory.

  - nss: Out-of-bounds read when importing curve25519 private key (CVE-2019-11719)

  - nss: PKCS#1 v1.5 signatures can be used for TLS 1.3 (CVE-2019-11727)

  - nss: Use-after-free in sftk_FreeSession due to improper refcounting (CVE-2019-11756)

  - nss: Check length of inputs for cryptographic primitives (CVE-2019-17006)

  - nss: TLS 1.3 HelloRetryRequest downgrade request sets client into invalid state (CVE-2019-17023)

  - nss: P-384 and P-521 implementation uses a side-channel vulnerable modular inversion function
    (CVE-2020-12400)

  - nss: ECDSA timing attack mitigation bypass (CVE-2020-12401)

  - nss: Side channel vulnerabilities during RSA key generation (CVE-2020-12402)

  - nss: CHACHA20-POLY1305 decryption with undersized tag leads to out-of-bounds read (CVE-2020-12403)

  - nss: Side channel attack on ECDSA signature generation (CVE-2020-6829)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-November/012876.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c6405af");
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-November/012877.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1352d2d8");
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-November/012878.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?68abfba7");
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-November/012879.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4a2823e");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/122.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/125.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/327.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/416.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17006");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(122, 125, 327, 416);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-softokn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-softokn-freebl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-softokn-freebl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'CentOS 7.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

pkgs = [
    {'reference':'nspr-4.25.0-2.el7_9', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'nspr-4.25.0-2.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'nspr-devel-4.25.0-2.el7_9', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'nspr-devel-4.25.0-2.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'nss-3.53.1-3.el7_9', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'nss-3.53.1-3.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'nss-devel-3.53.1-3.el7_9', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'nss-devel-3.53.1-3.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'nss-pkcs11-devel-3.53.1-3.el7_9', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'nss-pkcs11-devel-3.53.1-3.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'nss-softokn-3.53.1-6.el7_9', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'nss-softokn-3.53.1-6.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'nss-softokn-devel-3.53.1-6.el7_9', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'nss-softokn-devel-3.53.1-6.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'nss-softokn-freebl-3.53.1-6.el7_9', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'nss-softokn-freebl-3.53.1-6.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'nss-softokn-freebl-devel-3.53.1-6.el7_9', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'nss-softokn-freebl-devel-3.53.1-6.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'nss-sysinit-3.53.1-3.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'nss-tools-3.53.1-3.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'nss-util-3.53.1-1.el7_9', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'nss-util-3.53.1-1.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'nss-util-devel-3.53.1-1.el7_9', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'nss-util-devel-3.53.1-1.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +
    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nspr / nspr-devel / nss / etc');
}
