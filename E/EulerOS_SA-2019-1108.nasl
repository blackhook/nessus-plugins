#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123121);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2017-18360",
    "CVE-2018-10878",
    "CVE-2018-10881",
    "CVE-2018-18281",
    "CVE-2018-20169"
  );

  script_name(english:"EulerOS 2.0 SP3 : kernel (EulerOS-SA-2019-1108)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A flaw was discovered in the Linux kernel's USB
    subsystem in the __usb_get_extra_descriptor() function
    in the drivers/usb/core/usb.c which mishandles a size
    check during the reading of an extra descriptor data.
    By using a specially crafted USB device which sends a
    forged extra descriptor, an unprivileged user with
    physical access to the system can potentially cause a
    privilege escalation or trigger a system crash or lock
    up and thus to cause a denial of service
    (DoS).(CVE-2018-20169)

  - Since Linux kernel version 3.2, the mremap() syscall
    performs TLB flushes after dropping pagetable locks. If
    a syscall such as ftruncate() removes entries from the
    pagetables of a task that is in the middle of mremap(),
    a stale TLB entry can remain for a short time that
    permits access to a physical page after it has been
    released back to the page allocator and
    reused.(CVE-2018-18281)

  - A division-by-zero in set_termios(), when debugging is
    enabled, was found in the Linux kernel. When the
    [io_ti] driver is loaded, a local unprivileged attacker
    can request incorrect high transfer speed in the
    change_port_settings() in the
    drivers/usb/serial/io_ti.c so that the divisor value
    becomes zero and causes a system crash resulting in a
    denial of service. (CVE-2017-18360)

  - A flaw was found in the Linux kernel's ext4 filesystem.
    A local user can cause an out-of-bound access in
    ext4_get_group_info function, a denial of service, and
    a system crash by mounting and operating on a crafted
    ext4 filesystem image.(CVE-2018-10881)

  - A flaw was found in the Linux kernel's ext4 filesystem.
    A local user can cause an out-of-bounds write and a
    denial of service or unspecified other impact is
    possible by mounting and operating a crafted ext4
    filesystem image.(CVE-2018-10878)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1108
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f33765a");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20169");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-18281");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
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

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-514.44.5.10.h165",
        "kernel-debuginfo-3.10.0-514.44.5.10.h165",
        "kernel-debuginfo-common-x86_64-3.10.0-514.44.5.10.h165",
        "kernel-devel-3.10.0-514.44.5.10.h165",
        "kernel-headers-3.10.0-514.44.5.10.h165",
        "kernel-tools-3.10.0-514.44.5.10.h165",
        "kernel-tools-libs-3.10.0-514.44.5.10.h165",
        "perf-3.10.0-514.44.5.10.h165",
        "python-perf-3.10.0-514.44.5.10.h165"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
