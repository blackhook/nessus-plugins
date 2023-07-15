#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2022 Security Advisory ALAS2022-2022-043.
##

include('compat.inc');

if (description)
{
  script_id(164737);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/06");

  script_cve_id("CVE-2021-3981");

  script_name(english:"Amazon Linux 2022 :  (ALAS2022-2022-043)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2022 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by a vulnerability as referenced in the ALAS2022-2022-043 advisory.

  - A flaw in grub2 was found where its configuration file, known as grub.cfg, is being created with the wrong
    permission set allowing non privileged users to read its content. This represents a low severity
    confidentiality issue, as those users can eventually read any encrypted passwords present in grub.cfg.
    This flaw affects grub2 2.06 and previous versions. This issue has been fixed in grub upstream but no
    version with the fix is currently released. (CVE-2021-3981)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2022/ALAS-2022-043.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3981.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update --releasever=2022.0.20220419 grub2' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3981");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-aa64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-aa64-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-aa64-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-aa64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-x64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-x64-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-x64-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-x64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-emu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-emu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-emu-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-pc-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-tools-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-tools-efi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-tools-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-tools-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-tools-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-tools-minimal-debuginfo");
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
    {'reference':'grub2-common-2.06-22.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-debuginfo-2.06-22.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-debuginfo-2.06-22.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-debugsource-2.06-22.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-debugsource-2.06-22.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-aa64-2.06-22.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-aa64-cdboot-2.06-22.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-aa64-ec2-2.06-22.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-aa64-modules-2.06-22.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-x64-2.06-22.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-x64-cdboot-2.06-22.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-x64-ec2-2.06-22.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-x64-modules-2.06-22.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-emu-2.06-22.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-emu-2.06-22.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-emu-debuginfo-2.06-22.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-emu-debuginfo-2.06-22.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-emu-modules-2.06-22.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-emu-modules-2.06-22.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-pc-2.06-22.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-pc-modules-2.06-22.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-2.06-22.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-2.06-22.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-debuginfo-2.06-22.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-debuginfo-2.06-22.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-efi-2.06-22.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-efi-debuginfo-2.06-22.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-extra-2.06-22.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-extra-2.06-22.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-extra-debuginfo-2.06-22.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-extra-debuginfo-2.06-22.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-minimal-2.06-22.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-minimal-2.06-22.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-minimal-debuginfo-2.06-22.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-minimal-debuginfo-2.06-22.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "grub2-common / grub2-debuginfo / grub2-debugsource / etc");
}