#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2022 Security Advisory ALAS2022-2022-223.
##

include('compat.inc');

if (description)
{
  script_id(168582);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/12");

  script_cve_id("CVE-2021-43527");

  script_name(english:"Amazon Linux 2022 : nss (ALAS2022-2022-223)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2022 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of nss installed on the remote host is prior to 3.83.0-1. It is, therefore, affected by a vulnerability as
referenced in the ALAS2022-2022-223 advisory.

  - NSS (Network Security Services) versions prior to 3.73 or 3.68.1 ESR are vulnerable to a heap overflow
    when handling DER-encoded DSA or RSA-PSS signatures. Applications using NSS for handling signatures
    encoded within CMS, S/MIME, PKCS \#7, or PKCS \#12 are likely to be impacted. Applications using NSS for
    certificate validation or other TLS, X.509, OCSP or CRL functionality may be impacted, depending on how
    they configure NSS. *Note: This vulnerability does NOT impact Mozilla Firefox.* However, email clients and
    PDF viewers that use NSS for signature verification, such as Thunderbird, LibreOffice, Evolution and
    Evince are believed to be impacted. This vulnerability affects NSS < 3.73 and NSS < 3.68.1.
    (CVE-2021-43527)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2022/ALAS-2022-223.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-43527.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update nss' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43527");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nspr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-softokn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-softokn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-softokn-freebl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-softokn-freebl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-softokn-freebl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-sysinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2022");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver != "-2022")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2022", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'nspr-4.35.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nspr-4.35.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nspr-4.35.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nspr-debuginfo-4.35.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nspr-debuginfo-4.35.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nspr-debuginfo-4.35.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nspr-devel-4.35.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nspr-devel-4.35.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nspr-devel-4.35.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-3.83.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-3.83.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-3.83.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-debuginfo-3.83.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-debuginfo-3.83.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-debuginfo-3.83.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-debugsource-3.83.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-debugsource-3.83.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-debugsource-3.83.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-devel-3.83.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-devel-3.83.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-devel-3.83.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-pkcs11-devel-3.83.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-pkcs11-devel-3.83.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-pkcs11-devel-3.83.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-3.83.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-3.83.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-3.83.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-debuginfo-3.83.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-debuginfo-3.83.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-debuginfo-3.83.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-devel-3.83.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-devel-3.83.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-devel-3.83.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-freebl-3.83.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-freebl-3.83.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-freebl-3.83.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-freebl-debuginfo-3.83.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-freebl-debuginfo-3.83.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-freebl-debuginfo-3.83.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-freebl-devel-3.83.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-freebl-devel-3.83.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-softokn-freebl-devel-3.83.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-sysinit-3.83.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-sysinit-3.83.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-sysinit-3.83.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-sysinit-debuginfo-3.83.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-sysinit-debuginfo-3.83.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-sysinit-debuginfo-3.83.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-tools-3.83.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-tools-3.83.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-tools-3.83.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-tools-debuginfo-3.83.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-tools-debuginfo-3.83.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-tools-debuginfo-3.83.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-util-3.83.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-util-3.83.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-util-3.83.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-util-debuginfo-3.83.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-util-debuginfo-3.83.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-util-debuginfo-3.83.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-util-devel-3.83.0-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-util-devel-3.83.0-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-util-devel-3.83.0-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr / nspr-debuginfo / nspr-devel / etc");
}