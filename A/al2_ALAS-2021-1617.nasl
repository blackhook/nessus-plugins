##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2021-1617.
##

include('compat.inc');

if (description)
{
  script_id(147909);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/19");

  script_cve_id("CVE-2020-13765", "CVE-2020-16092");
  script_xref(name:"ALAS", value:"2021-1617");

  script_name(english:"Amazon Linux 2 : qemu (ALAS-2021-1617)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of qemu installed on the remote host is prior to 3.1.0-8. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2021-1617 advisory.

  - rom_copy() in hw/core/loader.c in QEMU 4.0 and 4.1.0 does not validate the relationship between two
    addresses, which allows attackers to trigger an invalid memory copy operation. (CVE-2020-13765)

  - In QEMU through 5.0.0, an assertion failure can occur in the network packet processing. This issue affects
    the e1000e and vmxnet3 network devices. A malicious guest user/process could use this flaw to abort the
    QEMU process on the host, resulting in a denial of service condition in net_tx_pkt_add_raw_fragment in
    hw/net/net_tx_pkt.c. (CVE-2020-16092)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2021-1617.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-13765");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-16092");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update qemu' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13765");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/19");

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
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

pkgs = [
    {'reference':'ivshmem-tools-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ivshmem-tools-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ivshmem-tools-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-alsa-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-alsa-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-alsa-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-oss-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-oss-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-oss-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-pa-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-pa-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-pa-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-sdl-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-sdl-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-sdl-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-curl-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-curl-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-curl-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-dmg-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-dmg-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-dmg-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-iscsi-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-iscsi-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-iscsi-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-nfs-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-nfs-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-nfs-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-rbd-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-rbd-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-ssh-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-ssh-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-ssh-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-common-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-common-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-common-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-debuginfo-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-debuginfo-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-debuginfo-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-guest-agent-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-guest-agent-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-guest-agent-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-img-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-img-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-img-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-kvm-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-kvm-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-kvm-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-kvm-core-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-kvm-core-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-kvm-core-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-aarch64-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-aarch64-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-aarch64-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-aarch64-core-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-aarch64-core-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-aarch64-core-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-x86-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-x86-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-x86-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-x86-core-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-x86-core-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-x86-core-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-curses-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-curses-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-curses-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-gtk-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-gtk-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-gtk-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-sdl-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-sdl-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-sdl-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-binfmt-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-binfmt-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-binfmt-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-static-3.1.0-8.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-static-3.1.0-8.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-static-3.1.0-8.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ivshmem-tools / qemu / qemu-audio-alsa / etc");
}