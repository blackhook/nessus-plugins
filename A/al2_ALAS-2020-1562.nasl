##
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1562.
##

include('compat.inc');

if (description)
{
  script_id(142726);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/11");

  script_cve_id("CVE-2019-20382", "CVE-2020-14364");
  script_xref(name:"ALAS", value:"2020-1562");

  script_name(english:"Amazon Linux 2 : ivshmem-tools (ALAS-2020-1562)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS2-2020-1562 advisory.

  - QEMU 4.1.0 has a memory leak in zrle_compress_data in ui/vnc-enc-zrle.c during a VNC disconnect operation
    because libz is misused, resulting in a situation where memory allocated in deflateInit2 is not freed in
    deflateEnd. (CVE-2019-20382)

  - An out-of-bounds read/write access flaw was found in the USB emulator of the QEMU in versions before
    5.2.0. This issue occurs while processing USB packets from a guest when USBDevice 'setup_len' exceeds its
    'data_buf[4096]' in the do_token_in, do_token_out routines. This flaw allows a guest user to crash the
    QEMU process, resulting in a denial of service, or the potential execution of arbitrary code with the
    privileges of the QEMU process on the host. (CVE-2020-14364)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1562.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-20382");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14364");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update qemu' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14364");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/11");

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

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'ivshmem-tools-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'ivshmem-tools-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'ivshmem-tools-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-audio-alsa-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-audio-alsa-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-audio-alsa-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-audio-oss-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-audio-oss-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-audio-oss-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-audio-pa-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-audio-pa-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-audio-pa-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-audio-sdl-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-audio-sdl-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-audio-sdl-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-block-curl-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-block-curl-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-block-curl-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-block-dmg-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-block-dmg-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-block-dmg-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-block-iscsi-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-block-iscsi-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-block-iscsi-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-block-nfs-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-block-nfs-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-block-nfs-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-block-rbd-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-block-rbd-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-block-ssh-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-block-ssh-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-block-ssh-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-common-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-common-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-common-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-debuginfo-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-debuginfo-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-debuginfo-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-guest-agent-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-guest-agent-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-guest-agent-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-img-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-img-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-img-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-kvm-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-kvm-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-kvm-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-kvm-core-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-kvm-core-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-kvm-core-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-system-aarch64-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-system-aarch64-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-system-aarch64-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-system-aarch64-core-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-system-aarch64-core-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-system-aarch64-core-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-system-x86-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-system-x86-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-system-x86-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-system-x86-core-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-system-x86-core-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-system-x86-core-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-ui-curses-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-ui-curses-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-ui-curses-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-ui-gtk-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-ui-gtk-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-ui-gtk-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-ui-sdl-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-ui-sdl-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-ui-sdl-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-user-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-user-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-user-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-user-binfmt-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-user-binfmt-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-user-binfmt-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'qemu-user-static-3.1.0-8.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'qemu-user-static-3.1.0-8.amzn2.0.5', 'cpu':'i686', 'release':'AL2'},
    {'reference':'qemu-user-static-3.1.0-8.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2'}
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