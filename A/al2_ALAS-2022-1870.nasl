#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2022-1870.
##

include('compat.inc');

if (description)
{
  script_id(167227);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/09");

  script_cve_id("CVE-2019-12749", "CVE-2020-12049");

  script_name(english:"Amazon Linux 2 : dbus (ALAS-2022-1870)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of dbus installed on the remote host is prior to 1.10.24-7. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2022-1870 advisory.

  - dbus before 1.10.28, 1.12.x before 1.12.16, and 1.13.x before 1.13.12, as used in DBusServer in Canonical
    Upstart in Ubuntu 14.04 (and in some, less common, uses of dbus-daemon), allows cookie spoofing because of
    symlink mishandling in the reference implementation of DBUS_COOKIE_SHA1 in the libdbus library. (This only
    affects the DBUS_COOKIE_SHA1 authentication mechanism.) A malicious client with write access to its own
    home directory could manipulate a ~/.dbus-keyrings symlink to cause a DBusServer with a different uid to
    read and write in unintended locations. In the worst case, this could result in the DBusServer reusing a
    cookie that is known to the malicious client, and treating that cookie as evidence that a subsequent
    client connection came from an attacker-chosen uid, allowing authentication bypass. (CVE-2019-12749)

  - An issue was discovered in dbus >= 1.3.0 before 1.12.18. The DBusServer in libdbus, as used in dbus-
    daemon, leaks file descriptors when a message exceeds the per-message file descriptor limit. A local
    attacker with access to the D-Bus system bus or another system service's private AF_UNIX socket could use
    this to make the system service reach its file descriptor limit, denying service to subsequent D-Bus
    clients. (CVE-2020-12049)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2022-1870.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-12749.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-12049.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update dbus' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12749");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dbus-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dbus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dbus-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dbus-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dbus-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dbus-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'dbus-1.10.24-7.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dbus-1.10.24-7.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dbus-1.10.24-7.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dbus-debuginfo-1.10.24-7.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dbus-debuginfo-1.10.24-7.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dbus-debuginfo-1.10.24-7.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dbus-devel-1.10.24-7.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dbus-devel-1.10.24-7.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dbus-devel-1.10.24-7.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dbus-doc-1.10.24-7.amzn2.0.2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dbus-libs-1.10.24-7.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dbus-libs-1.10.24-7.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dbus-libs-1.10.24-7.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dbus-tests-1.10.24-7.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dbus-tests-1.10.24-7.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dbus-tests-1.10.24-7.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dbus-x11-1.10.24-7.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dbus-x11-1.10.24-7.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dbus-x11-1.10.24-7.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dbus / dbus-debuginfo / dbus-devel / etc");
}