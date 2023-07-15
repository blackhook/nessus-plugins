#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130815);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2019-14814",
    "CVE-2019-14815",
    "CVE-2019-14816",
    "CVE-2019-15098",
    "CVE-2019-15099",
    "CVE-2019-15504",
    "CVE-2019-15505",
    "CVE-2019-16089",
    "CVE-2019-16233",
    "CVE-2019-16714"
  );

  script_name(english:"EulerOS 2.0 SP8 : kernel (EulerOS-SA-2019-2106)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The kernel package contains the Linux kernel (vmlinuz),
    the core of any Linux operating system. The kernel
    handles the basic functions of the operating system:
    memory allocation, process allocation, device input and
    output, etc.Security
    Fix(es):drivers/media/usb/dvb-usb/technisat-usb2.c in
    the Linux kernel through 5.2.9 has an out-of-bounds
    read via crafted USB device traffic (which may be
    remote via usbip or usbredir).(CVE-2019-15505)An issue
    was discovered in the Linux kernel through 5.2.13.
    nbd_genl_status in drivers/blockbd.c does not check the
    nla_nest_start_noflag return
    value.(CVE-2019-16089)drivers/scsi/qla2xxx/qla_os.c in
    the Linux kernel 5.2.14 does not check the
    alloc_workqueue return value, leading to a NULL pointer
    dereference.(CVE-2019-16233)In the Linux kernel before
    5.2.14, rds6_inc_info_copy in net/rds/recv.c allows
    attackers to obtain sensitive information from kernel
    stack memory because tos and flags fields are not
    initialized.(CVE-2019-16714)drivers/
    net/wireless/rsi/rsi_91x_usb.c in the Linux kernel
    through 5.2.9 has a Double Free via crafted USB device
    traffic (which may be remote via usbip or
    usbredir).(CVE-2019-15504)There is heap-based buffer
    overflow in Linux kernel, all versions up to, excluding
    5.3, in the marvell wifi chip driver in Linux kernel,
    that allows local users to cause a denial of
    service(system crash) or possibly execute arbitrary
    code.(CVE-2019-14814)There is heap-based buffer
    overflow in marvell wifi chip driver in Linux
    kernel,allows local users to cause a denial of
    service(system crash) or possibly execute arbitrary
    code.(CVE-2019-14815)There is heap-based buffer
    overflow in kernel, all versions up to, excluding 5.3,
    in the marvell wifi chip driver in Linux kernel, that
    allows local users to cause a denial of service(system
    crash) or possibly execute arbitrary
    code.(CVE-2019-14816)drivers/
    net/wireless/ath/ath6kl/usb.c in the Linux kernel
    through 5.2.9 has a NULL pointer dereference via an
    incomplete address in an endpoint
    descriptor.(CVE-2019-15098)drivers/
    net/wireless/ath/ath10k/usb.c in the Linux kernel
    through 5.2.8 has a NULL pointer dereference via an
    incomplete address in an endpoint
    descriptor.(CVE-2019-15099)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2106
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e2f218e2");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["bpftool-4.19.36-vhulk1907.1.0.h475.eulerosv2r8",
        "kernel-4.19.36-vhulk1907.1.0.h475.eulerosv2r8",
        "kernel-devel-4.19.36-vhulk1907.1.0.h475.eulerosv2r8",
        "kernel-headers-4.19.36-vhulk1907.1.0.h475.eulerosv2r8",
        "kernel-source-4.19.36-vhulk1907.1.0.h475.eulerosv2r8",
        "kernel-tools-4.19.36-vhulk1907.1.0.h475.eulerosv2r8",
        "kernel-tools-libs-4.19.36-vhulk1907.1.0.h475.eulerosv2r8",
        "perf-4.19.36-vhulk1907.1.0.h475.eulerosv2r8",
        "python-perf-4.19.36-vhulk1907.1.0.h475.eulerosv2r8",
        "python3-perf-4.19.36-vhulk1907.1.0.h475.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
