#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104911);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-12188",
    "CVE-2017-12192",
    "CVE-2017-15299",
    "CVE-2017-15649",
    "CVE-2017-16525",
    "CVE-2017-16526",
    "CVE-2017-16527",
    "CVE-2017-16528",
    "CVE-2017-16529",
    "CVE-2017-16530",
    "CVE-2017-16531",
    "CVE-2017-16532",
    "CVE-2017-16533",
    "CVE-2017-16534",
    "CVE-2017-16535",
    "CVE-2017-16536",
    "CVE-2017-16537",
    "CVE-2017-16538"
  );

  script_name(english:"EulerOS 2.0 SP2 : kernel (EulerOS-SA-2017-1292)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A vulnerability was found in the key management
    subsystem of the Linux kernel. An update on an
    uninstantiated key could cause a kernel panic, leading
    to denial of service (DoS).(CVE-2017-15299)

  - It was found that fanout_add() in
    'net/packet/af_packet.c' in the Linux kernel, before
    version 4.13.6, allows local users to gain privileges
    via crafted system calls that trigger mishandling of
    packet_fanout data structures, because of a race
    condition (involving fanout_add and packet_do_bind)
    that leads to a use-after-free bug.(CVE-2017-15649)

  - The keyctl_read_key function in security/keys/keyctl.c
    in the Key Management subcomponent in the Linux kernel
    before 4.13.5 does not properly consider that a key may
    be possessed but negatively instantiated, which allows
    local users to cause a denial of service (OOPS and
    system crash) via a crafted KEYCTL_READ
    operation.(CVE-2017-12192)

  - The Linux kernel built with the KVM visualization
    support (CONFIG_KVM), with nested visualization(nVMX)
    feature enabled (nested=1), was vulnerable to a stack
    buffer overflow issue. The vulnerability could occur
    while traversing guest page table entries to resolve
    guest virtual address(gva). An L1 guest could use this
    flaw to crash the host kernel resulting in denial of
    service (DoS) or potentially execute arbitrary code on
    the host to gain privileges on the
    system.(CVE-2017-12188)

  - The imon_probe function in drivers/media/rc/imon.c in
    the Linux kernel through 4.13.11 allows local users to
    cause a denial of service (NULL pointer dereference and
    system crash) or possibly have unspecified other impact
    via a crafted USB device.(CVE-2017-16537)

  - drivers/media/usb/dvb-usb-v2/lmedm04.c in the Linux
    kernel through 4.13.11 allows local users to cause a
    denial of service (general protection fault and system
    crash) or possibly have unspecified other impact via a
    crafted USB device, related to a missing warm-start
    check and incorrect attach timing
    (dm04_lme2510_frontend_attach versus
    dm04_lme2510_tuner).(CVE-2017-16538)

  - The cx231xx_usb_probe function in
    drivers/media/usb/cx231xx/cx231xx-cards.c in the Linux
    kernel through 4.13.11 allows local users to cause a
    denial of service (NULL pointer dereference and system
    crash) or possibly have unspecified other impact via a
    crafted USB device.(CVE-2017-16536)

  - The usb_get_bos_descriptor function in
    drivers/usb/core/config.c in the Linux kernel before
    4.13.10 allows local users to cause a denial of service
    (out-of-bounds read and system crash) or possibly have
    unspecified other impact via a crafted USB
    device.(CVE-2017-16535)

  - The cdc_parse_cdc_header function in
    drivers/usb/core/message.c in the Linux kernel before
    4.13.6 allows local users to cause a denial of service
    (out-of-bounds read and system crash) or possibly have
    unspecified other impact via a crafted USB
    device.(CVE-2017-16534)

  - The usbhid_parse function in
    drivers/hid/usbhid/hid-core.c in the Linux kernel
    before 4.13.8 allows local users to cause a denial of
    service (out-of-bounds read and system crash) or
    possibly have unspecified other impact via a crafted
    USB device.(CVE-2017-16533)

  - The get_endpoints function in
    drivers/usb/misc/usbtest.c in the Linux kernel through
    4.13.11 allows local users to cause a denial of service
    (NULL pointer dereference and system crash) or possibly
    have unspecified other impact via a crafted USB
    device.(CVE-2017-16532)

  - drivers/usb/core/config.c in the Linux kernel before
    4.13.6 allows local users to cause a denial of service
    (out-of-bounds read and system crash) or possibly have
    unspecified other impact via a crafted USB device,
    related to the USB_DT_INTERFACE_ASSOCIATION
    descriptor.(CVE-2017-16531)

  - The uas driver in the Linux kernel before 4.13.6 allows
    local users to cause a denial of service (out-of-bounds
    read and system crash) or possibly have unspecified
    other impact via a crafted USB device, related to
    drivers/usb/storage/uas-detect.h and
    drivers/usb/storage/uas.c.(CVE-2017-16530)

  - The snd_usb_create_streams function in sound/usb/card.c
    in the Linux kernel before 4.13.6 allows local users to
    cause a denial of service (out-of-bounds read and
    system crash) or possibly have unspecified other impact
    via a crafted USB device.(CVE-2017-16529)

  - sound/core/seq_device.c in the Linux kernel before
    4.13.4 allows local users to cause a denial of service
    (snd_rawmidi_dev_seq_free use-after-free and system
    crash) or possibly have unspecified other impact via a
    crafted USB device.(CVE-2017-16528)

  - sound/usb/mixer.c in the Linux kernel before 4.13.8
    allows local users to cause a denial of service
    (snd_usb_mixer_interrupt use-after-free and system
    crash) or possibly have unspecified other impact via a
    crafted USB device.(CVE-2017-16527)

  - drivers/uwb/uwbd.c in the Linux kernel before 4.13.6
    allows local users to cause a denial of service
    (general protection fault and system crash) or possibly
    have unspecified other impact via a crafted USB
    device.(CVE-2017-16526)

  - The usb_serial_console_disconnect function in
    drivers/usb/serial/console.c in the Linux kernel before
    4.13.8 allows local users to cause a denial of service
    (use-after-free and system crash) or possibly have
    unspecified other impact via a crafted USB device,
    related to disconnection and failed
    setup.(CVE-2017-16525)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1292
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?88a509d0");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-327.59.59.46.h33",
        "kernel-debug-3.10.0-327.59.59.46.h33",
        "kernel-debug-devel-3.10.0-327.59.59.46.h33",
        "kernel-debuginfo-3.10.0-327.59.59.46.h33",
        "kernel-debuginfo-common-x86_64-3.10.0-327.59.59.46.h33",
        "kernel-devel-3.10.0-327.59.59.46.h33",
        "kernel-headers-3.10.0-327.59.59.46.h33",
        "kernel-tools-3.10.0-327.59.59.46.h33",
        "kernel-tools-libs-3.10.0-327.59.59.46.h33",
        "perf-3.10.0-327.59.59.46.h33",
        "python-perf-3.10.0-327.59.59.46.h33"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
