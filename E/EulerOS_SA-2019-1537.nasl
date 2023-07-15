#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124990);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2013-6383",
    "CVE-2014-3611",
    "CVE-2014-4667",
    "CVE-2015-8767",
    "CVE-2015-8955",
    "CVE-2015-8970",
    "CVE-2015-9004",
    "CVE-2016-5244",
    "CVE-2017-9074",
    "CVE-2017-13693",
    "CVE-2017-14497",
    "CVE-2017-15116",
    "CVE-2017-16529",
    "CVE-2017-16536",
    "CVE-2017-16650",
    "CVE-2017-16939",
    "CVE-2017-17449",
    "CVE-2018-1130",
    "CVE-2018-8087",
    "CVE-2018-10323"
  );
  script_bugtraq_id(63888, 68224, 70743);

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1537)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The kernel package contains the Linux kernel (vmlinuz),
    the core of any Linux operating system. The kernel
    handles the basic functions of the operating system:
    memory allocation, process allocation, device input and
    output, etc.Security Fix(es):A buffer overflow was
    discovered in tpacket_rcv() function in the Linux
    kernel since v4.6-rc1 through v4.13. A number of
    socket-related syscalls can be made to set up a
    configuration when each packet received by a network
    interface can cause writing up to 10 bytes to a kernel
    memory outside of a kernel buffer. This can cause
    unspecified kernel data corruption effects, including
    damage of in-memory and on-disk XFS
    data.(CVE-2017-14497)The qmi_wwan_bind function in
    driverset/usb/qmi_wwan.c in the Linux kernel through
    4.13.11 allows local users to cause a denial of service
    (divide-by-zero error and system crash) or possibly
    have unspecified other impact via a crafted USB
    device.(CVE-2017-16650)A race condition flaw was found
    in the way the Linux kernel's SCTP implementation
    handled sctp_accept() during the processing of
    heartbeat timeout events. A remote attacker could use
    this flaw to prevent further connections to be accepted
    by the SCTP server running on the system, resulting in
    a denial of service.(CVE-2015-8767)A race condition
    flaw was found in the way the Linux kernel's KVM
    subsystem handled PIT (Programmable Interval Timer)
    emulation. A guest user who has access to the PIT I/O
    ports could use this flaw to crash the
    host.(CVE-2014-3611)The Linux kernel is vulnerable to a
    memory leak in the
    driverset/wireless/mac80211_hwsim.c:hwsim_new_radio_nl(
    ) function. An attacker could exploit this to cause a
    potential denial of service.(CVE-2018-8087)An integer
    underflow flaw was found in the way the Linux kernel's
    Stream Control Transmission Protocol (SCTP)
    implementation processed certain COOKIE_ECHO packets.
    By sending a specially crafted SCTP packet, a remote
    attacker could use this flaw to prevent legitimate
    connections to a particular SCTP server socket to be
    made.(CVE-2014-4667)The cx231xx_usb_probe function in
    drivers/media/usb/cx231xx/cx231xx-cards.c in the Linux
    kernel through 4.13.11 allows local users to cause a
    denial of service (NULL pointer dereference and system
    crash) or possibly have unspecified other impact via a
    crafted USB device.(CVE-2017-16536)The
    snd_usb_create_streams function in sound/usb/card.c in
    the Linux kernel, before 4.13.6, allows local users to
    cause a denial of service (out-of-bounds read and
    system crash) or possibly have unspecified other impact
    via a crafted USB device.(CVE-2017-16529)A flaw was
    found in the Linux kernel's random number generator
    API. A null pointer dereference in the rngapi_reset
    function may result in denial of service, crashing the
    system.(CVE-2017-15116)The __netlink_deliver_tap_skb
    function in netetlink/af_netlink.c in the Linux kernel,
    through 4.14.4, does not restrict observations of
    Netlink messages to a single net namespace, when
    CONFIG_NLMON is enabled. This allows local users to
    obtain sensitive information by leveraging the
    CAP_NET_ADMIN capability to sniff an nlmon interface
    for all Netlink activity on the
    system.(CVE-2017-17449)arch/arm64/kernel/perf_event.c
    in the Linux kernel before 4.1 on arm64 platforms
    allows local users to gain privileges or cause a denial
    of service (invalid pointer dereference) via vectors
    involving events that are mishandled during a span of
    multiple HW PMUs.(CVE-2015-8955)The aac_compat_ioctl
    function in drivers/scsi/aacraid/linit.c in the Linux
    kernel before 3.11.8 does not require the CAP_SYS_RAWIO
    capability, which allows local users to bypass intended
    access restrictions via a crafted ioctl
    call.(CVE-2013-6383)Linux kernel before version
    4.16-rc7 is vulnerable to a null pointer dereference in
    dccp_write_xmit() function in net/dccp/output.c in that
    allows a local user to cause a denial of service by a
    number of certain crafted system
    calls.(CVE-2018-1130)The Linux kernel is vulerable to a
    use-after-free flaw when Transformation User
    configuration interface(CONFIG_XFRM_USER) compile-time
    configuration were enabled. This vulnerability occurs
    while closing a xfrm netlink socket in
    xfrm_dump_policy_done. A user/process could abuse this
    flaw to potentially escalate their privileges on a
    system.(CVE-2017-16939)A vulnerability was found in the
    Linux kernel in function rds_inc_info_copy of file
    net/rds/recv.c. The last field 'flags' of object
    'minfo' is not initialized. This can leak data
    previously at the flags location to
    userspace.(CVE-2016-5244)A flaw was found in the
    kernel's ACPI interpreter when it does not flush the
    operand cache and causes a kernel stack dump. This
    allows local users to obtain sensitive information from
    kernel memory and bypass the KASLR protection
    mechanism.(CVE-2017-13693)It was found that
    kernel/events/core.c in the Linux kernel mishandles
    counter grouping, which allows local users to gain
    privileges via a crafted application, related to the
    perf_pmu_register and perf_event_open
    functions.(CVE-2015-9004)The xfs_bmap_extents_to_btree
    function in fs/xfs/libxfs/xfs_bmap.c in the Linux
    kernel through 4.16.3 allows local users to cause a
    denial of service (xfs_bmapi_write NULL pointer
    dereference) via a crafted xfs
    image.(CVE-2018-10323)The lrw_crypt() function in
    'crypto/lrw.c' in the Linux kernel before 4.5 allows
    local users to cause a system crash and a denial of
    service by the NULL pointer dereference via accept(2)
    system call for AF_ALG socket without calling setkey()
    first to set a cipher key.(CVE-2015-8970)The IPv6
    fragmentation implementation in the Linux kernel does
    not consider that the nexthdr field may be associated
    with an invalid option, which allows local users to
    cause a denial of service (out-of-bounds read and BUG)
    or possibly have unspecified other impact via crafted
    socket and send system calls. Due to the nature of the
    flaw, privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.(CVE-2017-9074)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1537
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6bb8a3e5");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-9004");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-9074");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

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
