#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124797);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/09");

  script_cve_id(
    "CVE-2013-1059",
    "CVE-2013-2140",
    "CVE-2013-2164",
    "CVE-2013-2888",
    "CVE-2013-2889",
    "CVE-2013-2892",
    "CVE-2013-2929",
    "CVE-2013-2930",
    "CVE-2013-4125",
    "CVE-2013-4127",
    "CVE-2013-4162",
    "CVE-2013-4163",
    "CVE-2013-4205",
    "CVE-2013-4247",
    "CVE-2013-4270",
    "CVE-2013-4299",
    "CVE-2013-4300",
    "CVE-2013-4312",
    "CVE-2013-4343",
    "CVE-2013-4345"
  );
  script_bugtraq_id(
    60375,
    60414,
    60922,
    61166,
    61198,
    61411,
    61412,
    61636,
    61800,
    62042,
    62043,
    62049,
    62072,
    62360,
    62740,
    63183,
    64111,
    64318,
    64471
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : kernel (EulerOS-SA-2019-1473)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - net/ceph/auth_none.c in the Linux kernel through 3.10
    allows remote attackers to cause a denial of service
    (NULL pointer dereference and system crash) or possibly
    have unspecified other impact via an auth_reply message
    that triggers an attempted build_request
    operation.(CVE-2013-1059)

  - The dispatch_discard_io function in
    drivers/block/xen-blkback/blkback.c in the Xen blkback
    implementation in the Linux kernel before 3.10.5 allows
    guest OS users to cause a denial of service (data loss)
    via filesystem write operations on a read-only disk
    that supports the (1) BLKIF_OP_DISCARD (aka discard or
    TRIM) or (2) SCSI UNMAP feature.(CVE-2013-2140)

  - The mmc_ioctl_cdrom_read_data function in
    drivers/cdrom/cdrom.c in the Linux kernel through 3.10
    allows local users to obtain sensitive information from
    kernel memory via a read operation on a malfunctioning
    CD-ROM drive.(CVE-2013-2164)

  - Multiple array index errors in drivers/hid/hid-core.c
    in the Human Interface Device (HID) subsystem in the
    Linux kernel through 3.11 allow physically proximate
    attackers to execute arbitrary code or cause a denial
    of service (heap memory corruption) via a crafted
    device that provides an invalid Report
    ID.(CVE-2013-2888)

  - drivers/hid/hid-zpff.c in the Human Interface Device
    (HID) subsystem in the Linux kernel through 3.11, when
    CONFIG_HID_ZEROPLUS is enabled, allows physically
    proximate attackers to cause a denial of service
    (heap-based out-of-bounds write) via a crafted
    device.(CVE-2013-2889)

  - drivers/hid/hid-pl.c in the Human Interface Device
    (HID) subsystem in the Linux kernel through 3.11, when
    CONFIG_HID_PANTHERLORD is enabled, allows physically
    proximate attackers to cause a denial of service
    (heap-based out-of-bounds write) via a crafted
    device.(CVE-2013-2892)

  - A flaw was found in the way the get_dumpable() function
    return value was interpreted in the ptrace subsystem of
    the Linux kernel. When 'fs.suid_dumpable' was set to 2,
    a local, unprivileged local user could use this flaw to
    bypass intended ptrace restrictions and obtain
    potentially sensitive information.(CVE-2013-2929)

  - The perf_trace_event_perm function in
    kernel/trace/trace_event_perf.c in the Linux kernel
    before 3.12.2 does not properly restrict access to the
    perf subsystem, which allows local users to enable
    function tracing via a crafted
    application.(CVE-2013-2930)

  - The fib6_add_rt2node function in net/ipv6/ip6_fib.c in
    the IPv6 stack in the Linux kernel through 3.10.1 does
    not properly handle Router Advertisement (RA) messages
    in certain circumstances involving three routes that
    initially qualified for membership in an ECMP route set
    until a change occurred for one of the first two
    routes, which allows remote attackers to cause a denial
    of service (system crash) via a crafted sequence of
    messages.(CVE-2013-4125)

  - Use-after-free vulnerability in the
    vhost_net_set_backend function in drivers/vhost/net.c
    in the Linux kernel through 3.10.3 allows local users
    to cause a denial of service (OOPS and system crash)
    via vectors involving powering on a virtual
    machine.(CVE-2013-4127)

  - The udp_v6_push_pending_frames function in
    net/ipv6/udp.c in the IPv6 implementation in the Linux
    kernel through 3.10.3 makes an incorrect function call
    for pending data, which allows local users to cause a
    denial of service (BUG and system crash) via a crafted
    application that uses the UDP_CORK option in a
    setsockopt system call.(CVE-2013-4162)

  - The ip6_append_data_mtu function in
    net/ipv6/ip6_output.c in the IPv6 implementation in the
    Linux kernel through 3.10.3 does not properly maintain
    information about whether the IPV6_MTU setsockopt
    option had been specified, which allows local users to
    cause a denial of service (BUG and system crash) via a
    crafted application that uses the UDP_CORK option in a
    setsockopt system call.(CVE-2013-4163)

  - Memory leak in the unshare_userns function in
    kernel/user_namespace.c in the Linux kernel before
    3.10.6 allows local users to cause a denial of service
    (memory consumption) via an invalid CLONE_NEWUSER
    unshare call.(CVE-2013-4205)

  - Off-by-one error in the build_unc_path_to_root function
    in fs/cifs/connect.c in the Linux kernel before 3.9.6
    allows remote attackers to cause a denial of service
    (memory corruption and system crash) via a DFS share
    mount operation that triggers use of an unexpected DFS
    referral name length.(CVE-2013-4247)

  - The net_ctl_permissions function in net/sysctl_net.c in
    the Linux kernel before 3.11.5 does not properly
    determine uid and gid values, which allows local users
    to bypass intended /proc/sys/net restrictions via a
    crafted application.(CVE-2013-4270)

  - Interpretation conflict in
    drivers/md/dm-snap-persistent.c in the Linux kernel
    through 3.11.6 allows remote authenticated users to
    obtain sensitive information or modify data via a
    crafted mapping to a snapshot block
    device.(CVE-2013-4299)

  - The scm_check_creds function in net/core/scm.c in the
    Linux kernel before 3.11 performs a capability check in
    an incorrect namespace, which allows local users to
    gain privileges via PID spoofing.(CVE-2013-4300)

  - It was found that the Linux kernel did not properly
    account file descriptors passed over the unix socket
    against the process limit. A local user could use this
    flaw to exhaust all available memory on the
    system.(CVE-2013-4312)

  - Use-after-free vulnerability in drivers/net/tun.c in
    the Linux kernel through 3.11.1 allows local users to
    gain privileges by leveraging the CAP_NET_ADMIN
    capability and providing an invalid tuntap interface
    name in a TUNSETIFF ioctl call.(CVE-2013-4343)

  - Off-by-one error in the get_prng_bytes function in
    crypto/ansi_cprng.c in the Linux kernel through 3.11.4
    makes it easier for context-dependent attackers to
    defeat cryptographic protection mechanisms via multiple
    requests for small amounts of data, leading to improper
    management of the state of the consumed
    data.(CVE-2013-4345)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1473
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?461705d1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4300");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.6_42",
        "kernel-devel-3.10.0-862.14.1.6_42",
        "kernel-headers-3.10.0-862.14.1.6_42",
        "kernel-tools-3.10.0-862.14.1.6_42",
        "kernel-tools-libs-3.10.0-862.14.1.6_42",
        "kernel-tools-libs-devel-3.10.0-862.14.1.6_42",
        "perf-3.10.0-862.14.1.6_42",
        "python-perf-3.10.0-862.14.1.6_42"];

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
