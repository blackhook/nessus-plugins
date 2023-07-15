#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125585);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2016-8667",
    "CVE-2016-10155",
    "CVE-2017-7471",
    "CVE-2017-8309",
    "CVE-2017-8379",
    "CVE-2017-16845",
    "CVE-2017-18030",
    "CVE-2020-10756"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : qemu-kvm (EulerOS-SA-2019-1633)");

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
    safe and easy to use. Security Fix(es):Memory leak in
    hw/watchdog/wdt_i6300esb.c in QEMU (aka Quick Emulator)
    allows local guest OS privileged users to cause a
    denial of service (host memory consumption and QEMU
    process crash) via a large number of device unplug
    operations.(CVE-2016-10155)Memory leak in the
    audio/audio.c in QEMU (aka Quick Emulator) allows
    remote attackers to cause a denial of service (memory
    consumption) by repeatedly starting and stopping audio
    capture.(CVE-2017-8309)Memory leak in the keyboard
    input event handlers support in QEMU (aka Quick
    Emulator) allows local guest OS privileged users to
    cause a denial of service (host memory consumption) by
    rapidly generating large keyboard
    events.(CVE-2017-8379)hw/input/ps2.c in Qemu does not
    validate 'rptr' and 'count' values during guest
    migration, leading to out-of-bounds access.
    (CVE-2017-16845)The cirrus_invalidate_region function
    in hw/display/cirrus_vga.c in Qemu allows local OS
    guest privileged users to cause a denial of service
    (out-of-bounds array access and QEMU process crash) via
    vectors related to negative pitch.(CVE-2017-18030)Quick
    Emulator (Qemu) built with the VirtFS, host directory
    sharing via Plan 9 File System (9pfs) support, is
    vulnerable to an improper access control issue. It
    could occur while accessing files on a shared host
    directory. A privileged user inside guest could use
    this flaw to access host file system beyond the shared
    folder and potentially escalating their privileges on a
    host.(CVE-2017-7471)An out-of-bounds read vulnerability
    was found in the SLiRP networking implementation of the
    QEMU emulator. This flaw occurs in the
    icmp6_send_echoreply() routine while replying to an
    ICMP echo request, also known as ping. This flaw allows
    a malicious guest to leak the contents of the host
    memory, resulting in possible information disclosure.
    This flaw affects versions of libslirp before
    4.3.1.(CVE-2020-10756)The rc4030_write function in
    hw/dma/rc4030.c in QEMU (aka Quick Emulator) allows
    local guest OS administrators to cause a denial of
    service (divide-by-zero error and QEMU process crash)
    via a large interval timer reload value.(CVE-2016-8667)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1633
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?187ee9d3");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu-kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7471");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-16845");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["qemu-img-2.8.1-30.062",
        "qemu-kvm-2.8.1-30.062",
        "qemu-kvm-common-2.8.1-30.062",
        "qemu-kvm-tools-2.8.1-30.062"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-kvm");
}
