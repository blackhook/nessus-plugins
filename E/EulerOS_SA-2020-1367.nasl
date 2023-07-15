#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135154);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/06");

  script_cve_id(
    "CVE-2016-2858",
    "CVE-2016-8667",
    "CVE-2017-11434",
    "CVE-2017-12809",
    "CVE-2017-17381",
    "CVE-2017-8086",
    "CVE-2018-7858",
    "CVE-2019-12247",
    "CVE-2019-20175"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.6.0 : qemu-kvm (EulerOS-SA-2020-1367)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu-kvm packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - qemu-kvm is an open source virtualizer that provides
    hardware emulation for the KVM hypervisor. qemu-kvm
    acts as a virtual machine monitor together with the KVM
    kernel modules, and emulates the hardware for a full
    system such as a PC and its assocated peripherals. As
    qemu-kvm requires no host kernel patches to run, it is
    safe and easy to use.Security Fix(es):Memory leak in
    the v9fs_list_xattr function in hw/9pfs/9p-xattr.c in
    QEMU (aka Quick Emulator) allows local guest OS
    privileged users to cause a denial of service (memory
    consumption) via vectors involving the orig_value
    variable.(CVE-2017-8086)The dhcp_decode function in
    slirp/bootp.c in QEMU (aka Quick Emulator) allows local
    guest OS users to cause a denial of service
    (out-of-bounds read and QEMU process crash) via a
    crafted DHCP options string.(CVE-2017-11434)** DISPUTED
    ** QEMU 3.0.0 has an Integer Overflow because the
    qga/commands*.c files do not check the length of the
    argument list or the number of environment variables.
    NOTE: This has been disputed as not
    exploitable.(CVE-2019-12247)** DISPUTED ** An issue was
    discovered in ide_dma_cb() in hw/ide/core.c in QEMU
    2.4.0 through 4.2.0. The guest system can crash the
    QEMU process in the host system via a special
    SCSI_IOCTL_SEND_COMMAND. It hits an assertion that
    implies that the size of successful DMA transfers there
    must be a multiple of 512 (the size of a sector). NOTE:
    a member of the QEMU security team disputes the
    significance of this issue because a 'privileged guest
    user has many ways to cause similar DoS effect, without
    triggering this assert.'(CVE-2019-20175)QEMU (aka Quick
    Emulator), when built with the IDE disk and CD/DVD-ROM
    Emulator support, allows local guest OS privileged
    users to cause a denial of service (NULL pointer
    dereference and QEMU process crash) by flushing an
    empty CDROM device drive. (CVE-2017-12809)The Virtio
    Vring implementation in QEMU allows local OS guest
    users to cause a denial of service (divide-by-zero
    error and QEMU process crash) by unsetting vring
    alignment while updating Virtio rings.
    (CVE-2017-17381)The rc4030_write function in
    hw/dma/rc4030.c in QEMU (aka Quick Emulator) allows
    local guest OS administrators to cause a denial of
    service (divide-by-zero error and QEMU process crash)
    via a large interval timer reload value.
    (CVE-2016-8667)Quick Emulator (aka QEMU), when built
    with the Cirrus CLGD 54xx VGA Emulator support, allows
    local guest OS privileged users to cause a denial of
    service (out-of-bounds access and QEMU process crash)
    by leveraging incorrect region calculation when
    updating VGA display. (CVE-2018-7858)QEMU, when built
    with the Pseudo Random Number Generator (PRNG) back-end
    support, allows local guest OS users to cause a denial
    of service (process crash) via an entropy request,
    which triggers arbitrary stack based allocation and
    memory corruption.(CVE-2016-2858)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1367
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?93f008d3");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu-kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["qemu-img-2.8.1-30.443",
        "qemu-kvm-2.8.1-30.443",
        "qemu-kvm-common-2.8.1-30.443",
        "qemu-kvm-tools-2.8.1-30.443"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-kvm");
}
