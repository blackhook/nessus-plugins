#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2023-2060.
##

include('compat.inc');

if (description)
{
  script_id(176702);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/05");

  script_cve_id("CVE-2021-20257");
  script_xref(name:"IAVB", value:"2020-B-0075-S");

  script_name(english:"Amazon Linux 2 : qemu (ALAS-2023-2060)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of qemu installed on the remote host is prior to 3.1.0-8. It is, therefore, affected by a vulnerability as
referenced in the ALAS2-2023-2060 advisory.

  - An infinite loop flaw was found in the e1000 NIC emulator of the QEMU. This issue occurs while processing
    transmits (tx) descriptors in process_tx_desc if various descriptor fields are initialized with invalid
    values. This flaw allows a guest to consume CPU cycles on the host, resulting in a denial of service. The
    highest threat from this vulnerability is to system availability. (CVE-2021-20257)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2023-2060.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-20257.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update qemu' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20257");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ivshmem-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-audio-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-audio-oss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-audio-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-audio-sdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-block-dmg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-block-nfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-kvm-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-system-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-system-aarch64-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-system-x86-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-ui-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-ui-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-ui-sdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-user-binfmt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-user-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'ivshmem-tools-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ivshmem-tools-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ivshmem-tools-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-alsa-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-alsa-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-alsa-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-oss-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-oss-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-oss-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-pa-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-pa-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-pa-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-sdl-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-sdl-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-sdl-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-curl-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-curl-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-curl-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-dmg-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-dmg-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-dmg-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-iscsi-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-iscsi-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-iscsi-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-nfs-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-nfs-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-nfs-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-rbd-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-rbd-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-ssh-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-ssh-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-ssh-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-common-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-common-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-common-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-debuginfo-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-debuginfo-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-debuginfo-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-guest-agent-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-guest-agent-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-guest-agent-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-img-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-img-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-img-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-kvm-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-kvm-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-kvm-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-kvm-core-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-kvm-core-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-kvm-core-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-aarch64-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-aarch64-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-aarch64-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-aarch64-core-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-aarch64-core-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-aarch64-core-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-x86-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-x86-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-x86-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-x86-core-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-x86-core-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-x86-core-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-curses-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-curses-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-curses-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-gtk-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-gtk-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-gtk-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-sdl-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-sdl-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-sdl-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-binfmt-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-binfmt-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-binfmt-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-static-3.1.0-8.amzn2.0.9', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-static-3.1.0-8.amzn2.0.9', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-static-3.1.0-8.amzn2.0.9', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ivshmem-tools / qemu / qemu-audio-alsa / etc");
}