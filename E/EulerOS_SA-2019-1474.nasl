#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124798);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2013-2898",
    "CVE-2013-4514",
    "CVE-2014-1690",
    "CVE-2014-4656",
    "CVE-2014-8160",
    "CVE-2014-8559",
    "CVE-2014-9729",
    "CVE-2015-3212",
    "CVE-2015-7799",
    "CVE-2015-7872",
    "CVE-2016-4580",
    "CVE-2016-7910",
    "CVE-2016-10200",
    "CVE-2017-5972",
    "CVE-2017-11600",
    "CVE-2017-16532",
    "CVE-2018-1066",
    "CVE-2018-8781",
    "CVE-2018-11506",
    "CVE-2018-14615"
  );
  script_bugtraq_id(
    62056,
    63509,
    65180,
    68163,
    70854,
    72061,
    74964
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1474)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The x25_negotiate_facilities function in
    net/x25/x25_facilities.c in the Linux kernel before
    4.5.5 does not properly initialize a certain data
    structure, which allows attackers to obtain sensitive
    information from kernel stack memory via an X.25 Call
    Request.(CVE-2016-4580i1/4%0

  - A flaw was found in the Linux kernel's implementation
    of seq_file where a local attacker could manipulate
    memory in the put() function pointer. This could lead
    to memory corruption and possible privileged
    escalation.(CVE-2016-7910i1/4%0

  - A flaw was found in the way the Linux kernel's
    netfilter subsystem handled generic protocol tracking.
    As demonstrated in the Stream Control Transmission
    Protocol (SCTP) case, a remote attacker could use this
    flaw to bypass intended iptables rule restrictions when
    the associated connection tracking module was not
    loaded on the system.(CVE-2014-8160i1/4%0

  - The get_endpoints function in
    drivers/usb/misc/usbtest.c in the Linux kernel through
    4.13.11 allows local users to cause a denial of service
    (NULL pointer dereference and system crash) or possibly
    have unspecified other impact via a crafted USB
    device.(CVE-2017-16532i1/4%0

  - An integer overflow flaw was found in the way the Linux
    kernel's Advanced Linux Sound Architecture (ALSA)
    implementation handled user controls. A local,
    privileged user could use this flaw to crash the
    system.(CVE-2014-4656i1/4%0

  - The sr_do_ioctl function in drivers/scsi/sr_ioctl.c in
    the Linux kernel through 4.16.12 allows local users to
    cause a denial of service (stack-based buffer overflow)
    or possibly have unspecified other impact because sense
    buffers have different sizes at the CDROM layer and the
    SCSI layer.(CVE-2018-11506i1/4%0

  - A race condition flaw was found in the way the Linux
    kernel's SCTP implementation handled Address
    Configuration lists when performing Address
    Configuration Change (ASCONF). A local attacker could
    use this flaw to crash the system via a race condition
    triggered by setting certain ASCONF options on a
    socket.(CVE-2015-3212i1/4%0

  - A symlink size validation was missing in Linux kernels
    built with UDF file system (CONFIG_UDF_FS) support,
    allowing the corruption of kernel memory. An attacker
    able to mount a corrupted/malicious UDF file system
    image could cause the kernel to crash.(CVE-2014-9729i1/4%0

  - The Linux kernel before version 4.11 is vulnerable to a
    NULL pointer dereference in
    fs/cifs/cifsencrypt.c:setup_ntlmv2_rsp() that allows an
    attacker controlling a CIFS server to kernel panic a
    client that has this server mounted, because an empty
    TargetInfo field in an NTLMSSP setup negotiation
    response is mishandled during session
    recovery.(CVE-2018-1066i1/4%0

  - drivers/hid/hid-sensor-hub.c in the Human Interface
    Device (HID) subsystem in the Linux kernel through
    3.11, when CONFIG_HID_SENSOR_HUB is enabled, allows
    physically proximate attackers to obtain sensitive
    information from kernel memory via a crafted
    device.(CVE-2013-2898i1/4%0

  - An issue was discovered in the Linux kernel's F2FS
    filesystem code. A buffer overflow in
    truncate_inline_inode() in the fs/f2fs/inline.c
    function, when umounting a crafted f2fs image, can
    occur because a length value may be
    negative.(CVE-2018-14615i1/4%0

  - The help function in net/netfilter/nf_nat_irc.c in the
    Linux kernel before 3.12.8 allows remote attackers to
    obtain sensitive information from kernel memory by
    establishing an IRC DCC session in which incorrect
    packet data is transmitted during use of the NAT mangle
    feature.(CVE-2014-1690i1/4%0

  - It was found that the Linux kernel's keys subsystem did
    not correctly garbage collect uninstantiated keyrings.
    A local attacker could use this flaw to crash the
    system or, potentially, escalate their privileges on
    the system.(CVE-2015-7872i1/4%0

  - The TCP stack in the Linux kernel 3.x does not properly
    implement a SYN cookie protection mechanism for the
    case of a fast network connection, which allows remote
    attackers to cause a denial of service (CPU
    consumption) by sending many TCP SYN packets, as
    demonstrated by an attack against the kernel-3.10.0
    package in CentOS Linux 7. NOTE: third parties have
    been unable to discern any relationship between the
    GitHub Engineering finding and the Trigemini.c attack
    code.(CVE-2017-5972i1/4%0

  - The xfrm_migrate() function in the
    net/xfrm/xfrm_policy.c file in the Linux kernel built
    with CONFIG_XFRM_MIGRATE does not verify if the dir
    parameter is less than XFRM_POLICY_MAX. This allows a
    local attacker to cause a denial of service
    (out-of-bounds access) or possibly have unspecified
    other impact by sending a XFRM_MSG_MIGRATE netlink
    message. This flaw is present in the Linux kernel since
    an introduction of XFRM_MSG_MIGRATE in 2.6.21-rc1, up
    to 4.13-rc3.(CVE-2017-11600i1/4%0

  - A use-after-free flaw was found in the Linux kernel
    which enables a race condition in the L2TPv3 IP
    Encapsulation feature. A local user could use this flaw
    to escalate their privileges or crash the
    system.(CVE-2016-10200i1/4%0

  - A flaw was found in the way the Linux kernel's VFS
    subsystem handled file system locks. A local,
    unprivileged user could use this flaw to trigger a
    deadlock in the kernel, causing a denial of service on
    the system.(CVE-2014-8559i1/4%0

  - Multiple buffer overflows in
    drivers/staging/wlags49_h2/wl_priv.c in the Linux
    kernel before 3.12 allow local users to cause a denial
    of service or possibly have unspecified other impact by
    leveraging the CAP_NET_ADMIN capability and providing a
    long station-name string, related to the (1)
    wvlan_uil_put_info and (2) wvlan_set_station_nickname
    functions.(CVE-2013-4514i1/4%0

  - The udl_fb_mmap function in
    drivers/gpu/drm/udl/udl_fb.c at the Linux kernel
    version 3.4 and up to and including 4.15 has an
    integer-overflow vulnerability allowing local users
    with access to the udldrmfb driver to obtain full read
    and write permissions on kernel physical pages,
    resulting in a code execution in kernel
    space.(CVE-2018-8781i1/4%0

  - A flaw was discovered in the Linux kernel where issuing
    certain ioctl() -s commands to the '/dev/ppp' device
    file could lead to a NULL pointer dereference. A
    privileged user could use this flaw to cause a kernel
    crash and denial of service.(CVE-2015-7799i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1474
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca0c9141");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7910");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-8781");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["kernel-4.19.28-1.2.117",
        "kernel-devel-4.19.28-1.2.117",
        "kernel-headers-4.19.28-1.2.117",
        "kernel-tools-4.19.28-1.2.117",
        "kernel-tools-libs-4.19.28-1.2.117",
        "kernel-tools-libs-devel-4.19.28-1.2.117",
        "perf-4.19.28-1.2.117",
        "python-perf-4.19.28-1.2.117"];

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
