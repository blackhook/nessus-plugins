#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2022 Security Advisory ALAS2022-2022-179.
##

include('compat.inc');

if (description)
{
  script_id(167016);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/05");

  script_cve_id("CVE-2021-43860", "CVE-2022-21682");

  script_name(english:"Amazon Linux 2022 :  (ALAS2022-2022-179)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2022 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2022-2022-179 advisory.

  - Flatpak is a Linux application sandboxing and distribution framework. Prior to versions 1.12.3 and 1.10.6,
    Flatpak doesn't properly validate that the permissions displayed to the user for an app at install time
    match the actual permissions granted to the app at runtime, in the case that there's a null byte in the
    metadata file of an app. Therefore apps can grant themselves permissions without the consent of the user.
    Flatpak shows permissions to the user during install by reading them from the xa.metadata key in the
    commit metadata. This cannot contain a null terminator, because it is an untrusted GVariant. Flatpak
    compares these permissions to the *actual* metadata, from the metadata file to ensure it wasn't lied to.
    However, the actual metadata contents are loaded in several places where they are read as simple C-style
    strings. That means that, if the metadata file includes a null terminator, only the content of the file
    from *before* the terminator gets compared to xa.metadata. Thus, any permissions that appear in the
    metadata file after a null terminator are applied at runtime but not shown to the user. So maliciously
    crafted apps can give themselves hidden permissions. Users who have Flatpaks installed from untrusted
    sources are at risk in case the Flatpak has a maliciously crafted metadata file, either initially or in an
    update. This issue is patched in versions 1.12.3 and 1.10.6. As a workaround, users can manually check the
    permissions of installed apps by checking the metadata file or the xa.metadata key on the commit metadata.
    (CVE-2021-43860)

  - Flatpak is a Linux application sandboxing and distribution framework. A path traversal vulnerability
    affects versions of Flatpak prior to 1.12.3 and 1.10.6. flatpak-builder applies `finish-args` last in the
    build. At this point the build directory will have the full access that is specified in the manifest, so
    running `flatpak build` against it will gain those permissions. Normally this will not be done, so this is
    not problem. However, if `--mirror-screenshots-url` is specified, then flatpak-builder will launch
    `flatpak build --nofilesystem=host appstream-utils mirror-screenshots` after finalization, which can lead
    to issues even with the `--nofilesystem=host` protection. In normal use, the only issue is that these
    empty directories can be created wherever the user has write permissions. However, a malicious application
    could replace the `appstream-util` binary and potentially do something more hostile. This has been
    resolved in Flatpak 1.12.3 and 1.10.6 by changing the behaviour of `--nofilesystem=home` and
    `--nofilesystem=host`. (CVE-2022-21682)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2022/ALAS-2022-179.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-43860.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-21682.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update flatpak --releasever=2022.0.20221102' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43860");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:flatpak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:flatpak-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:flatpak-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:flatpak-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:flatpak-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:flatpak-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:flatpak-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:flatpak-session-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:flatpak-session-helper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:flatpak-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:flatpak-tests-debuginfo");
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
    {'reference':'flatpak-1.12.4-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-1.12.4-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-1.12.4-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-debuginfo-1.12.4-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-debuginfo-1.12.4-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-debuginfo-1.12.4-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-debugsource-1.12.4-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-debugsource-1.12.4-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-debugsource-1.12.4-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-devel-1.12.4-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-devel-1.12.4-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-devel-1.12.4-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-libs-1.12.4-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-libs-1.12.4-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-libs-1.12.4-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-libs-debuginfo-1.12.4-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-libs-debuginfo-1.12.4-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-libs-debuginfo-1.12.4-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-selinux-1.12.4-1.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-session-helper-1.12.4-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-session-helper-1.12.4-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-session-helper-1.12.4-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-session-helper-debuginfo-1.12.4-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-session-helper-debuginfo-1.12.4-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-session-helper-debuginfo-1.12.4-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-tests-1.12.4-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-tests-1.12.4-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-tests-1.12.4-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-tests-debuginfo-1.12.4-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-tests-debuginfo-1.12.4-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-tests-debuginfo-1.12.4-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flatpak / flatpak-debuginfo / flatpak-debugsource / etc");
}