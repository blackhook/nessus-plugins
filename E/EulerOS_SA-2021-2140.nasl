#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151419);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-15239",
    "CVE-2019-19078",
    "CVE-2019-9456",
    "CVE-2020-0305",
    "CVE-2020-0427",
    "CVE-2020-0431",
    "CVE-2020-10773",
    "CVE-2020-11668",
    "CVE-2020-12654",
    "CVE-2020-14331",
    "CVE-2020-14351",
    "CVE-2020-14386",
    "CVE-2020-15436",
    "CVE-2020-25645",
    "CVE-2020-25656",
    "CVE-2020-25669",
    "CVE-2020-25704",
    "CVE-2020-25705",
    "CVE-2020-28974",
    "CVE-2020-29370",
    "CVE-2020-29661"
  );
  script_xref(name:"CEA-ID", value:"CEA-2020-0138");

  script_name(english:"EulerOS Virtualization 3.0.2.2 : kernel (EulerOS-SA-2021-2140)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A memory leak in the ath10k_usb_hif_tx_sg() function in
    drivers/net/wireless/ath/ath10k/usb.c in the Linux
    kernel through 5.3.11 allows attackers to cause a
    denial of service (memory consumption) by triggering
    usb_submit_urb() failures, aka
    CID-b8d17e7d93d2.(CVE-2019-19078)

  - In the Linux kernel before 5.6.1,
    drivers/media/usb/gspca/xirlink_cit.c (aka the Xirlink
    camera USB driver) mishandles invalid descriptors, aka
    CID-a246b4d54770.(CVE-2020-11668)

  - An issue was found in Linux kernel before 5.5.4.
    mwifiex_ret_wmm_get_status() in
    drivers/net/wireless/marvell/mwifiex/wmm.c allows a
    remote AP to trigger a heap-based buffer overflow
    because of an incorrect memcpy, aka
    CID-3a9b153c5591.(CVE-2020-12654)

  - A flaw was found in the way the Linux kernel's
    networking subsystem handled the write queue between
    TCP disconnection and re-connections. A local attacker
    could use this flaw to trigger multiple use-after-free
    conditions potentially escalating their privileges on
    the system.(CVE-2019-15239)

  - A use-after-free flaw was found in the way the Linux
    kernel's filesystem subsystem handled a race condition
    in the chrdev_open function. This flaw allows a
    privileged local user to starve the resources, causing
    a denial of service or potentially escalating their
    privileges. The highest threat from this vulnerability
    is to confidentiality, integrity, as well as system
    availability.(CVE-2020-0305)

  - A flaw was found in the Linux pinctrl system. It is
    possible to trigger an of bounds read due to a use
    after free. This could lead to local information
    disclosure with no additional execution privileges
    needed.(CVE-2020-0427)

  - A stack information leak flaw was found in s390/s390x
    in the Linux kernel's memory manager functionality,
    where it incorrectly writes to the
    /proc/sys/vm/cmm_timeout file. This flaw allows a local
    user to see the kernel data.(CVE-2020-10773)

  - A flaw was found in the Linux kernel's implementation
    of the invert video code on VGA consoles when a local
    attacker attempts to resize the console, calling an
    ioctl VT_RESIZE, which causes an out-of-bounds write to
    occur. This flaw allows a local user with access to the
    VGA console to crash the system, potentially escalating
    their privileges on the system. The highest threat from
    this vulnerability is to data confidentiality and
    integrity as well as system
    availability.(CVE-2020-14331)

  - A flaw was found in the Linux kernel. A use-after-free
    memory flaw was found in the perf subsystem allowing a
    local attacker with permission to monitor perf events
    to corrupt memory and possibly escalate privileges. The
    highest threat from this vulnerability is to data
    confidentiality and integrity as well as system
    availability.(CVE-2020-14351)

  - A flaw was found in the Linux kernel before 5.9-rc4.
    Memory corruption can be exploited to gain root
    privileges from unprivileged processes. The highest
    threat from this vulnerability is to data
    confidentiality and integrity.(CVE-2020-14386)

  - Use-after-free vulnerability in fs/block_dev.c in the
    Linux kernel before 5.8 allows local users to gain
    privileges or cause a denial of service by leveraging
    improper access to a certain error
    field.(CVE-2020-15436)

  - A flaw was found in the Linux kernel in versions before
    5.9-rc7. Traffic between two Geneve endpoints may be
    unencrypted when IPsec is configured to encrypt traffic
    for the specific UDP port used by the GENEVE tunnel
    allowing anyone between the two endpoints to read the
    traffic unencrypted. The main threat from this
    vulnerability is to data
    confidentiality.(CVE-2020-25645)

  - A flaw was found in the Linux kernel. A use-after-free
    was found in the way the console subsystem was using
    ioctls KDGKBSENT and KDSKBSENT. A local user could use
    this flaw to get read memory access out of bounds. The
    highest threat from this vulnerability is to data
    confidentiality.(CVE-2020-25656)

  - Bodong Zhao discovered a use-after-free in the Sun
    keyboard driver implementation in the Linux kernel. A
    local attacker could use this to cause a denial of
    service or possibly execute arbitrary
    code.(CVE-2020-25669)

  - A flaw memory leak in the Linux kernel performance
    monitoring subsystem was found in the way if using
    PERF_EVENT_IOC_SET_FILTER. A local user could use this
    flaw to starve the resources causing denial of
    service.(CVE-2020-25704)

  - A flaw in ICMP packets in the Linux kernel may allow an
    attacker to quickly scan open UDP ports. This flaw
    allows an off-path remote attacker to effectively
    bypass source port UDP randomization. Software that
    relies on UDP source port randomization are indirectly
    affected as well on the Linux Based Products (RUGGEDCOM
    RM1224: All versions between v5.0 and v6.4, SCALANCE
    M-800: All versions between v5.0 and v6.4, SCALANCE
    S615: All versions between v5.0 and v6.4, SCALANCE
    SC-600: All versions prior to v2.1.3, SCALANCE W1750D:
    v8.3.0.1, v8.6.0, and v8.7.0, SIMATIC Cloud Connect 7:
    All versions, SIMATIC MV500 Family: All versions,
    SIMATIC NET CP 1243-1 (incl. SIPLUS variants): Versions
    3.1.39 and later, SIMATIC NET CP 1243-7 LTE EU:
    Version(CVE-2020-25705)

  - A slab-out-of-bounds read in fbcon in the Linux kernel
    before 5.9.7 could be used by local attackers to read
    privileged information or potentially crash the kernel,
    aka CID-3c4e0dff2095. This occurs because
    KD_FONT_OP_COPY in drivers/tty/vt/vt.c can be used for
    manipulations such as font height.(CVE-2020-28974)

  - An issue was discovered in kmem_cache_alloc_bulk in
    mm/slub.c in the Linux kernel before 5.5.11. The
    slowpath lacks the required TID increment, aka
    CID-fd4d9c7d0c71.(CVE-2020-29370)

  - A locking issue was discovered in the tty subsystem of
    the Linux kernel through 5.9.13.
    drivers/tty/tty_jobctrl.c allows a use-after-free
    attack against TIOCSPGRP, aka
    CID-54ffccbf053b.(CVE-2020-29661)

  - A flaw was found in the USB monitor driver of the Linux
    kernel. This flaw allows an attacker with physical
    access to the system to crash the system or potentially
    escalate their privileges(CVE-2019-9456)

  - A flaw out of bounds write in the Linux kernel human
    interface devices subsystem was found in the way user
    calls find key code by index. A local user could use
    this flaw to crash the system or escalate privileges on
    the system.(CVE-2020-0431)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2140
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3064040");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-29661");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.2.2") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.2");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.6_77",
        "kernel-devel-3.10.0-862.14.1.6_77",
        "kernel-headers-3.10.0-862.14.1.6_77",
        "kernel-tools-3.10.0-862.14.1.6_77",
        "kernel-tools-libs-3.10.0-862.14.1.6_77",
        "perf-3.10.0-862.14.1.6_77",
        "python-perf-3.10.0-862.14.1.6_77"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
