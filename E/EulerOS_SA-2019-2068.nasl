#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129261);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2018-1093",
    "CVE-2018-13406",
    "CVE-2018-20856",
    "CVE-2019-10638",
    "CVE-2019-10639",
    "CVE-2019-11487",
    "CVE-2019-11833",
    "CVE-2019-11884",
    "CVE-2019-3874"
  );

  script_name(english:"EulerOS 2.0 SP3 : kernel (EulerOS-SA-2019-2068)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - An issue was discovered in the Linux kernel before
    4.18.7. In block/blk-core.c, there is an
    __blk_drain_queue() use-after-free because a certain
    error case is mishandled.(CVE-2018-20856)

  - In the Linux kernel before 5.1.7, a device can be
    tracked by an attacker using the IP ID values the
    kernel produces for connection-less protocols (e.g.,
    UDP and ICMP). When such traffic is sent to multiple
    destination IP addresses, it is possible to obtain hash
    collisions (of indices to the counter array) and
    thereby obtain the hashing key (via enumeration). An
    attack may be conducted by hosting a crafted web page
    that uses WebRTC or gQUIC to force UDP traffic to
    attacker-controlled IP addresses.(CVE-2019-10638)

  - The Linux kernel 4.x (starting from 4.1) and 5.x before
    5.0.8 allows Information Exposure (partial kernel
    address disclosure), leading to a KASLR bypass.
    Specifically, it is possible to extract the KASLR
    kernel image offset using the IP ID values the kernel
    produces for connection-less protocols (e.g., UDP and
    ICMP). When such traffic is sent to multiple
    destination IP addresses, it is possible to obtain hash
    collisions (of indices to the counter array) and
    thereby obtain the hashing key (via enumeration). This
    key contains enough bits from a kernel address (of a
    static variable) so when the key is extracted (via
    enumeration), the offset of the kernel image is
    exposed. This attack can be carried out remotely, by
    the attacker forcing the target device to send UDP or
    ICMP (or certain other) traffic to attacker-controlled
    IP addresses. Forcing a server to send UDP traffic is
    trivial if the server is a DNS server. ICMP traffic is
    trivial if the server answers ICMP Echo requests
    (ping). For client targets, if the target visits the
    attacker's web page, then WebRTC or gQUIC can be used
    to force UDP traffic to attacker-controlled IP
    addresses.(CVE-2019-10639)

  - The Linux kernel was found vulnerable to an integer
    overflow in the
    drivers/video/fbdev/uvesafb.c:uvesafb_setcmap()
    function. The vulnerability could result in local
    attackers being able to crash the kernel or potentially
    elevate privileges.(CVE-2018-13406)

  - The SCTP socket buffer used by a userspace application
    is not accounted by the cgroups subsystem. An attacker
    can use this flaw to cause a denial of service
    attack.(CVE-2019-3874)

  - The Linux kernel before 5.1-rc5 allows
    page-i1/4z_refcount reference count overflow, with
    resultant use-after-free issues, if about 140 GiB of
    RAM exists. This is related to fs/fuse/dev.c,
    fs/pipe.c, fs/splice.c, include/linux/mm.h,
    include/linux/pipe_fs_i.h, kernel/trace/trace.c,
    mm/gup.c, and mm/hugetlb.c. It can occur with FUSE
    requests.(CVE-2019-11487)

  - A flaw was found in the Linux kernel's implementation
    of ext4 extent management. The kernel doesn't correctly
    initialize memory regions in the extent tree block
    which may be exported to a local user to obtain
    sensitive information by reading empty/uninitialized
    data from the filesystem.(CVE-2019-11833)

  - A flaw was found in the Linux kernel's implementation
    of the Bluetooth Human Interface Device Protocol
    (HIDP). A local attacker with access permissions to the
    Bluetooth device can issue an IOCTL which will trigger
    the do_hidp_sock_ioctl function in
    net/bluetooth/hidp/sock.c.c. This function can leak
    potentially sensitive information from the kernel stack
    memory via a HIDPCONNADD command because a name field
    may not be correctly NULL terminated.(CVE-2019-11884)

  - The Linux kernel is vulnerable to an out-of-bounds read
    in ext4/balloc.c:ext4_valid_block_bitmap() function. An
    attacker could trick a legitimate user or a privileged
    attacker could exploit this by mounting a crafted ext4
    image to cause a crash.(CVE-2018-1093)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2068
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1059e72a");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/24");

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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-514.44.5.10.h221",
        "kernel-debuginfo-3.10.0-514.44.5.10.h221",
        "kernel-debuginfo-common-x86_64-3.10.0-514.44.5.10.h221",
        "kernel-devel-3.10.0-514.44.5.10.h221",
        "kernel-headers-3.10.0-514.44.5.10.h221",
        "kernel-tools-3.10.0-514.44.5.10.h221",
        "kernel-tools-libs-3.10.0-514.44.5.10.h221",
        "perf-3.10.0-514.44.5.10.h221",
        "python-perf-3.10.0-514.44.5.10.h221"];

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
