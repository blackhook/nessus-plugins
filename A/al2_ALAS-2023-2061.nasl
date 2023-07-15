#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2023-2061.
##

include('compat.inc');

if (description)
{
  script_id(176677);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/06");

  script_cve_id(
    "CVE-2021-3392",
    "CVE-2021-3527",
    "CVE-2021-3930",
    "CVE-2021-4207",
    "CVE-2021-20196",
    "CVE-2022-4144"
  );
  script_xref(name:"IAVB", value:"2020-B-0075-S");
  script_xref(name:"IAVB", value:"2022-B-0057");

  script_name(english:"Amazon Linux 2 : qemu (ALAS-2023-2061)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of qemu installed on the remote host is prior to 3.1.0-8. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2023-2061 advisory.

  - A NULL pointer dereference flaw was found in the floppy disk emulator of QEMU. This issue occurs while
    processing read/write ioport commands if the selected floppy drive is not initialized with a block device.
    This flaw allows a privileged guest user to crash the QEMU process on the host, resulting in a denial of
    service. The highest threat from this vulnerability is to system availability. (CVE-2021-20196)

  - A use-after-free flaw was found in the MegaRAID emulator of QEMU. This issue occurs while processing SCSI
    I/O requests in the case of an error mptsas_free_request() that does not dequeue the request object 'req'
    from a pending requests queue. This flaw allows a privileged guest user to crash the QEMU process on the
    host, resulting in a denial of service. Versions between 2.10.0 and 5.2.0 are potentially affected.
    (CVE-2021-3392)

  - A flaw was found in the USB redirector device (usb-redir) of QEMU. Small USB packets are combined into a
    single, large transfer request, to reduce the overhead and improve performance. The combined size of the
    bulk transfer is used to dynamically allocate a variable length array (VLA) on the stack without proper
    validation. Since the total size is not bounded, a malicious guest could use this flaw to influence the
    array length and cause the QEMU process to perform an excessive allocation on the stack, resulting in a
    denial of service. (CVE-2021-3527)

  - An off-by-one error was found in the SCSI device emulation in QEMU. It could occur while processing MODE
    SELECT commands in mode_sense_page() if the 'page' argument was set to MODE_PAGE_ALLS (0x3f). A malicious
    guest could use this flaw to potentially crash QEMU, resulting in a denial of service condition.
    (CVE-2021-3930)

  - A flaw was found in the QXL display device emulation in QEMU. A double fetch of guest controlled values
    `cursor->header.width` and `cursor->header.height` can lead to the allocation of a small cursor object
    followed by a subsequent heap-based buffer overflow. A malicious privileged guest user could use this flaw
    to crash the QEMU process on the host or potentially execute arbitrary code within the context of the QEMU
    process. (CVE-2021-4207)

  - An out-of-bounds read flaw was found in the QXL display device emulation in QEMU. The qxl_phys2virt()
    function does not check the size of the structure pointed to by the guest physical address, potentially
    reading past the end of the bar space into adjacent pages. A malicious guest user could use this flaw to
    crash the QEMU process on the host causing a denial of service condition. (CVE-2022-4144)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2023-2061.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-20196.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3392.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3527.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3930.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4207.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-4144.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update qemu' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4207");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
    {'reference':'ivshmem-tools-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ivshmem-tools-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ivshmem-tools-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-alsa-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-alsa-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-alsa-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-oss-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-oss-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-oss-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-pa-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-pa-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-pa-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-sdl-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-sdl-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-sdl-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-curl-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-curl-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-curl-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-dmg-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-dmg-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-dmg-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-iscsi-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-iscsi-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-iscsi-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-nfs-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-nfs-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-nfs-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-rbd-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-rbd-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-ssh-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-ssh-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-ssh-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-common-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-common-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-common-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-debuginfo-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-debuginfo-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-debuginfo-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-guest-agent-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-guest-agent-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-guest-agent-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-img-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-img-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-img-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-kvm-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-kvm-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-kvm-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-kvm-core-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-kvm-core-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-kvm-core-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-aarch64-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-aarch64-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-aarch64-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-aarch64-core-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-aarch64-core-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-aarch64-core-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-x86-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-x86-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-x86-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-x86-core-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-x86-core-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-system-x86-core-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-curses-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-curses-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-curses-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-gtk-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-gtk-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-gtk-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-sdl-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-sdl-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-sdl-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-binfmt-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-binfmt-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-binfmt-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-static-3.1.0-8.amzn2.0.10', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-static-3.1.0-8.amzn2.0.10', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-user-static-3.1.0-8.amzn2.0.10', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ivshmem-tools / qemu / qemu-audio-alsa / etc");
}