#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104910);
  script_version("3.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-1000380",
    "CVE-2017-15299",
    "CVE-2017-16525",
    "CVE-2017-16526",
    "CVE-2017-16529",
    "CVE-2017-16530",
    "CVE-2017-16531",
    "CVE-2017-16532",
    "CVE-2017-16533",
    "CVE-2017-16534",
    "CVE-2017-16535",
    "CVE-2017-16536",
    "CVE-2017-16537",
    "CVE-2017-16538",
    "CVE-2017-16643",
    "CVE-2017-16644",
    "CVE-2017-16645",
    "CVE-2017-16649",
    "CVE-2017-16650"
  );

  script_name(english:"EulerOS 2.0 SP1 : kernel (EulerOS-SA-2017-1291)");
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

  - The usb_serial_console_disconnect function in
    drivers/usb/serial/console.c in the Linux kernel before
    4.13.8 allows local users to cause a denial of service
    (use-after-free and system crash) or possibly have
    unspecified other impact via a crafted USB device,
    related to disconnection and failed
    setup.(CVE-2017-16525)

  - drivers/uwb/uwbd.c in the Linux kernel before 4.13.6
    allows local users to cause a denial of service
    (general protection fault and system crash) or possibly
    have unspecified other impact via a crafted USB
    device.(CVE-2017-16526)

  - drivers/usb/core/config.c in the Linux kernel before
    4.13.6 allows local users to cause a denial of service
    (out-of-bounds read and system crash) or possibly have
    unspecified other impact via a crafted USB device,
    related to the USB_DT_INTERFACE_ASSOCIATION
    descriptor.(CVE-2017-16531)

  - The get_endpoints function in
    drivers/usb/misc/usbtest.c in the Linux kernel through
    4.13.11 allows local users to cause a denial of service
    (NULL pointer dereference and system crash) or possibly
    have unspecified other impact via a crafted USB
    device.(CVE-2017-16532)

  - The usbhid_parse function in
    drivers/hid/usbhid/hid-core.c in the Linux kernel
    before 4.13.8 allows local users to cause a denial of
    service (out-of-bounds read and system crash) or
    possibly have unspecified other impact via a crafted
    USB device.(CVE-2017-16533)

  - The uas driver in the Linux kernel before 4.13.6 allows
    local users to cause a denial of service (out-of-bounds
    read and system crash) or possibly have unspecified
    other impact via a crafted USB device, related to
    drivers/usb/storage/uas-detect.h and
    drivers/usb/storage/uas.c.(CVE-2017-16530)

  - The usb_get_bos_descriptor function in
    drivers/usb/core/config.c in the Linux kernel before
    4.13.10 allows local users to cause a denial of service
    (out-of-bounds read and system crash) or possibly have
    unspecified other impact via a crafted USB
    device.(CVE-2017-16535)

  - A flaw was found that sound/core/timer.c in the Linux
    kernel before 4.11.5 is vulnerable to a data race in
    the ALSA /dev/snd/timer driver resulting in local users
    being able to read information belonging to other
    users. Uninitialized memory contents may be disclosed
    when a read and an ioctl happen at the same
    time.(CVE-2017-1000380)

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

  - The ims_pcu_get_cdc_union_desc function in
    drivers/input/misc/ims-pcu.c in the Linux kernel
    through 4.13.11 allows local users to cause a denial of
    service (ims_pcu_parse_cdc_data out-of-bounds read and
    system crash) or possibly have unspecified other impact
    via a crafted USB device.(CVE-2017-16645)

  - The parse_hid_report_descriptor function in
    drivers/input/tablet/gtco.c in the Linux kernel before
    4.13.11 allows local users to cause a denial of service
    (out-of-bounds read and system crash) or possibly have
    unspecified other impact via a crafted USB
    device.(CVE-2017-16643)

  - The hdpvr_probe function in
    drivers/media/usb/hdpvr/hdpvr-core.c in the Linux
    kernel through 4.13.11 allows local users to cause a
    denial of service (improper error handling and system
    crash) or possibly have unspecified other impact via a
    crafted USB device.(CVE-2017-16644)

  - The cdc_parse_cdc_header function in
    drivers/usb/core/message.c in the Linux kernel before
    4.13.6 allows local users to cause a denial of service
    (out-of-bounds read and system crash) or possibly have
    unspecified other impact via a crafted USB
    device.(CVE-2017-16534)

  - The qmi_wwan_bind function in
    drivers/net/usb/qmi_wwan.c in the Linux kernel through
    4.13.11 allows local users to cause a denial of service
    (divide-by-zero error and system crash) or possibly
    have unspecified other impact via a crafted USB
    device.(CVE-2017-16650)

  - The usbnet_generic_cdc_bind function in
    drivers/net/usb/cdc_ether.c in the Linux kernel through
    4.13.11 allows local users to cause a denial of service
    (divide-by-zero error and system crash) or possibly
    have unspecified other impact via a crafted USB
    device.(CVE-2017-16649)

  - The snd_usb_create_streams function in sound/usb/card.c
    in the Linux kernel before 4.13.6 allows local users to
    cause a denial of service (out-of-bounds read and
    system crash) or possibly have unspecified other impact
    via a crafted USB device.(CVE-2017-16529)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1291
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e77fd1c");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debug");
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
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-229.49.1.155",
        "kernel-debug-3.10.0-229.49.1.155",
        "kernel-debuginfo-3.10.0-229.49.1.155",
        "kernel-debuginfo-common-x86_64-3.10.0-229.49.1.155",
        "kernel-devel-3.10.0-229.49.1.155",
        "kernel-headers-3.10.0-229.49.1.155",
        "kernel-tools-3.10.0-229.49.1.155",
        "kernel-tools-libs-3.10.0-229.49.1.155",
        "perf-3.10.0-229.49.1.155",
        "python-perf-3.10.0-229.49.1.155"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

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
