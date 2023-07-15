#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2022 Security Advisory ALAS2022-2022-041.
##

include('compat.inc');

if (description)
{
  script_id(164713);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-0778");
  script_xref(name:"IAVA", value:"2022-A-0121-S");

  script_name(english:"Amazon Linux 2022 :  (ALAS2022-2022-041)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2022 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by a vulnerability as referenced in the ALAS2022-2022-041 advisory.

  - The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop
    forever for non-prime moduli. Internally this function is used when parsing certificates that contain
    elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point
    encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has
    invalid explicit curve parameters. Since certificate parsing happens prior to verification of the
    certificate signature, any process that parses an externally supplied certificate may thus be subject to a
    denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they
    can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients
    consuming server certificates - TLS servers consuming client certificates - Hosting providers taking
    certificates or private keys from customers - Certificate authorities parsing certification requests from
    subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that
    use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS
    issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate
    which makes it slightly harder to trigger the infinite loop. However any operation which requires the
    public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-
    signed certificate to trigger the loop during verification of the certificate signature. This issue
    affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the
    15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected
    1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc). (CVE-2022-0778)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2022/ALAS-2022-041.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0778.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update --releasever=2022.0.20220315 openssl' to update your system.
 Run 'dnf update --releasever=2022.0.20220315 openssl1.1' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0778");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl1.1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl1.1-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl1.1-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2022");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
var os_ver = os_ver[1];
if (os_ver != "-2022")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2022", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'openssl-3.0.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-3.0.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-3.0.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debuginfo-3.0.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debuginfo-3.0.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debuginfo-3.0.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debugsource-3.0.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debugsource-3.0.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debugsource-3.0.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-devel-3.0.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-devel-3.0.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-devel-3.0.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-3.0.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-3.0.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-3.0.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-debuginfo-3.0.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-debuginfo-3.0.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-debuginfo-3.0.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-perl-3.0.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-perl-3.0.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-perl-3.0.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl1.1-1.1.1l-2.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl1.1-1.1.1l-2.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl1.1-1.1.1l-2.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl1.1-debuginfo-1.1.1l-2.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl1.1-debuginfo-1.1.1l-2.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl1.1-debuginfo-1.1.1l-2.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl1.1-debugsource-1.1.1l-2.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl1.1-debugsource-1.1.1l-2.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl1.1-debugsource-1.1.1l-2.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl1.1-devel-1.1.1l-2.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl1.1-devel-1.1.1l-2.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl1.1-devel-1.1.1l-2.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-debuginfo / openssl-debugsource / etc");
}