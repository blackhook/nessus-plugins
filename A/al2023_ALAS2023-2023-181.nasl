#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2023-181.
##

include('compat.inc');

if (description)
{
  script_id(176345);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id(
    "CVE-2023-0464",
    "CVE-2023-0465",
    "CVE-2023-0466",
    "CVE-2023-1255"
  );
  script_xref(name:"IAVA", value:"2023-A-0158");

  script_name(english:"Amazon Linux 2023 : openssl, openssl-devel, openssl-libs (ALAS2023-2023-181)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2023-181 advisory.

  - A security vulnerability has been identified in all supported versions of OpenSSL related to the
    verification of X.509 certificate chains that include policy constraints. Attackers may be able to exploit
    this vulnerability by creating a malicious certificate chain that triggers exponential use of
    computational resources, leading to a denial-of-service (DoS) attack on affected systems. Policy
    processing is disabled by default but can be enabled by passing the `-policy' argument to the command line
    utilities or by calling the `X509_VERIFY_PARAM_set1_policies()' function. (CVE-2023-0464)

  - Applications that use a non-default option when verifying certificates may be vulnerable to an attack from
    a malicious CA to circumvent certain checks. Invalid certificate policies in leaf certificates are
    silently ignored by OpenSSL and other certificate policy checks are skipped for that certificate. A
    malicious CA could use this to deliberately assert invalid certificate policies in order to circumvent
    policy checking on the certificate altogether. Policy processing is disabled by default but can be enabled
    by passing the `-policy' argument to the command line utilities or by calling the
    `X509_VERIFY_PARAM_set1_policies()' function. (CVE-2023-0465)

  - The function X509_VERIFY_PARAM_add0_policy() is documented to implicitly enable the certificate policy
    check when doing certificate verification. However the implementation of the function does not enable the
    check which allows certificates with invalid or incorrect policies to pass the certificate verification.
    As suddenly enabling the policy check could break existing deployments it was decided to keep the existing
    behavior of the X509_VERIFY_PARAM_add0_policy() function. Instead the applications that require OpenSSL to
    perform certificate policy check need to use X509_VERIFY_PARAM_set1_policies() or explicitly enable the
    policy check by calling X509_VERIFY_PARAM_set_flags() with the X509_V_FLAG_POLICY_CHECK flag argument.
    Certificate policy checks are disabled by default in OpenSSL and are not commonly used by applications.
    (CVE-2023-0466)

  - Issue summary: The AES-XTS cipher decryption implementation for 64 bit ARM platform contains a bug that
    could cause it to read past the input buffer, leading to a crash. Impact summary: Applications that use
    the AES-XTS algorithm on the 64 bit ARM platform can crash in rare circumstances. The AES-XTS algorithm is
    usually used for disk encryption. The AES-XTS cipher decryption implementation for 64 bit ARM platform
    will read past the end of the ciphertext buffer if the ciphertext size is 4 mod 5 in 16 byte blocks, e.g.
    144 bytes or 1024 bytes. If the memory after the ciphertext buffer is unmapped, this will trigger a crash
    which results in a denial of service. If an attacker can control the size and location of the ciphertext
    buffer being decrypted by an application using AES-XTS on 64 bit ARM, the application is affected. This is
    fairly unlikely making this issue a Low severity one. (CVE-2023-1255)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2023-181.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-0464.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-0465.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-0466.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-1255.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update openssl --releasever 2023.0.20230517' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0466");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'openssl-3.0.8-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-3.0.8-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-3.0.8-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debuginfo-3.0.8-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debuginfo-3.0.8-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debuginfo-3.0.8-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debugsource-3.0.8-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debugsource-3.0.8-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debugsource-3.0.8-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-devel-3.0.8-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-devel-3.0.8-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-devel-3.0.8-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-3.0.8-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-3.0.8-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-3.0.8-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-debuginfo-3.0.8-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-debuginfo-3.0.8-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-debuginfo-3.0.8-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-perl-3.0.8-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-perl-3.0.8-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-perl-3.0.8-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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