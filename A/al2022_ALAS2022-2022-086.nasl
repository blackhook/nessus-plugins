#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2022 Security Advisory ALAS2022-2022-086.
##

include('compat.inc');

if (description)
{
  script_id(164755);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2021-3995", "CVE-2021-3996");

  script_name(english:"Amazon Linux 2022 :  (ALAS2022-2022-086)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2022 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2022-2022-086 advisory.

  - A logic error was found in the libmount library of util-linux in the function that allows an unprivileged
    user to unmount a FUSE filesystem. This flaw allows an unprivileged local attacker to unmount FUSE
    filesystems that belong to certain other users who have a UID that is a prefix of the UID of the attacker
    in its string form. An attacker may use this flaw to cause a denial of service to applications that use
    the affected filesystems. (CVE-2021-3995)

  - A logic error was found in the libmount library of util-linux in the function that allows an unprivileged
    user to unmount a FUSE filesystem. This flaw allows a local user on a vulnerable system to unmount other
    users' filesystems that are either world-writable themselves (like /tmp) or mounted in a world-writable
    directory. An attacker may use this flaw to cause a denial of service to applications that use the
    affected filesystems. (CVE-2021-3996)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2022/ALAS-2022-086.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3995.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3996.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update --releasever=2022.0.20220518 util-linux' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3996");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libblkid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libblkid-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libblkid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libfdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libfdisk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libfdisk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libmount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libmount-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libmount-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsmartcols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsmartcols-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsmartcols-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libuuid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libuuid-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libuuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-libmount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-libmount-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:util-linux-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:util-linux-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:util-linux-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:util-linux-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:util-linux-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:util-linux-user-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:uuidd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:uuidd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2022");
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
    {'reference':'libblkid-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libblkid-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libblkid-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libblkid-debuginfo-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libblkid-debuginfo-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libblkid-debuginfo-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libblkid-devel-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libblkid-devel-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libblkid-devel-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libfdisk-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libfdisk-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libfdisk-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libfdisk-debuginfo-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libfdisk-debuginfo-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libfdisk-debuginfo-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libfdisk-devel-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libfdisk-devel-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libfdisk-devel-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmount-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmount-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmount-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmount-debuginfo-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmount-debuginfo-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmount-debuginfo-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmount-devel-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmount-devel-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmount-devel-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmartcols-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmartcols-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmartcols-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmartcols-debuginfo-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmartcols-debuginfo-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmartcols-debuginfo-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmartcols-devel-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmartcols-devel-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmartcols-devel-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libuuid-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libuuid-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libuuid-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libuuid-debuginfo-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libuuid-debuginfo-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libuuid-debuginfo-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libuuid-devel-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libuuid-devel-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libuuid-devel-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libmount-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libmount-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libmount-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libmount-debuginfo-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libmount-debuginfo-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libmount-debuginfo-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-core-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-core-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-core-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-core-debuginfo-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-core-debuginfo-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-core-debuginfo-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-debuginfo-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-debuginfo-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-debuginfo-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-debugsource-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-debugsource-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-debugsource-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-user-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-user-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-user-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-user-debuginfo-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-user-debuginfo-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-user-debuginfo-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'uuidd-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'uuidd-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'uuidd-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'uuidd-debuginfo-2.37.4-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'uuidd-debuginfo-2.37.4-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'uuidd-debuginfo-2.37.4-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libblkid / libblkid-debuginfo / libblkid-devel / etc");
}