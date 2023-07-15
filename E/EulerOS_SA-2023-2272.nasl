#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177979);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id(
    "CVE-2022-4269",
    "CVE-2022-27672",
    "CVE-2023-0045",
    "CVE-2023-0240",
    "CVE-2023-0461",
    "CVE-2023-0597",
    "CVE-2023-1073",
    "CVE-2023-1074",
    "CVE-2023-1075",
    "CVE-2023-1076",
    "CVE-2023-1095",
    "CVE-2023-1118",
    "CVE-2023-1382",
    "CVE-2023-23586",
    "CVE-2023-26545",
    "CVE-2023-28327",
    "CVE-2023-28328"
  );

  script_name(english:"EulerOS 2.0 SP11 : kernel (EulerOS-SA-2023-2272)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - When SMT is enabled, certain AMD processors may speculatively execute instructions using a target from the
    sibling thread after an SMT mode switch potentially resulting in information disclosure. (CVE-2022-27672)

  - A flaw was found in the Linux kernel Traffic Control (TC) subsystem. Using a specific networking
    configuration (redirecting egress packets to ingress using TC action 'mirred') a local unprivileged user
    could trigger a CPU soft lockup (ABBA deadlock) when the transport protocol in use (TCP or SCTP) does a
    retransmission, resulting in a denial of service condition. (CVE-2022-4269)

  - The current implementation of the prctl syscall does not issue an IBPB immediately during the syscall. The
    ib_prctl_set function updates the Thread Information Flags (TIFs) for the task and updates the SPEC_CTRL
    MSR on the function __speculation_ctrl_update, but the IBPB is only issued on the next schedule, when the
    TIF bits are checked. This leaves the victim vulnerable to values already injected on the BTB, prior to
    the prctl syscall. The patch that added the support for the conditional mitigation via prctl
    (ib_prctl_set) dates back to the kernel 4.9.176. We recommend upgrading past commit
    a664ec9158eeddd75121d39c9a0758016097fa96 (CVE-2023-0045)

  - There is a logic error in io_uring's implementation which can be used to trigger a use-after-free
    vulnerability leading to privilege escalation. In the io_prep_async_work function the assumption that the
    last io_grab_identity call cannot return false is not true, and in this case the function will use the
    init_cred or the previous linked requests identity to do operations instead of using the current identity.
    This can lead to reference counting issues causing use-after-free. We recommend upgrading past version
    5.10.161. (CVE-2023-0240)

  - There is a use-after-free vulnerability in the Linux Kernel which can be exploited to achieve local
    privilege escalation. To reach the vulnerability kernel configuration flag CONFIG_TLS or
    CONFIG_XFRM_ESPINTCP has to be configured, but the operation does not require any privilege. There is a
    use-after-free bug of icsk_ulp_data of a struct inet_connection_sock. When CONFIG_TLS is enabled, user can
    install a tls context (struct tls_context) on a connected tcp socket. The context is not cleared if this
    socket is disconnected and reused as a listener. If a new socket is created from the listener, the context
    is inherited and vulnerable. The setsockopt TCP_ULP operation does not require any privilege. We recommend
    upgrading past commit 2c02d41d71f90a5168391b6a5f2954112ba2307c (CVE-2023-0461)

  - A flaw possibility of memory leak in the Linux kernel cpu_entry_area mapping of X86 CPU data to memory was
    found in the way user can guess location of exception stack(s) or other important data. A local user could
    use this flaw to get access to some important data with expected location in memory. (CVE-2023-0597)

  - A memory corruption flaw was found in the Linux kernel's human interface device (HID) subsystem in how a
    user inserts a malicious USB device. This flaw allows a local user to crash or potentially escalate their
    privileges on the system. (CVE-2023-1073)

  - A memory leak flaw was found in the Linux kernel's Stream Control Transmission Protocol. This issue may
    occur when a user starts a malicious networking service and someone connects to this service. This could
    allow a local user to starve resources, causing a denial of service. (CVE-2023-1074)

  - A flaw was found in the Linux Kernel. The tls_is_tx_ready() incorrectly checks for list emptiness,
    potentially accessing a type confused entry to the list_head, leaking the last byte of the confused field
    that overlaps with rec->tx_ready. (CVE-2023-1075)

  - A flaw was found in the Linux Kernel. The tun/tap sockets have their socket UID hardcoded to 0 due to a
    type confusion in their initialization function. While it will be often correct, as tuntap devices require
    CAP_NET_ADMIN, it may not always be the case, e.g., a non-root user only having that capability. This
    would make tun/tap sockets being incorrectly treated in filtering/routing decisions, possibly bypassing
    network filters. (CVE-2023-1076)

  - In nf_tables_updtable, if nf_tables_table_enable returns an error, nft_trans_destroy is called to free the
    transaction object. nft_trans_destroy() calls list_del(), but the transaction was never placed on a list
    -- the list head is all zeroes, this results in a NULL pointer dereference. (CVE-2023-1095)

  - A flaw use after free in the Linux kernel integrated infrared receiver/transceiver driver was found in the
    way user detaching rc device. A local user could use this flaw to crash the system or potentially escalate
    their privileges on the system. (CVE-2023-1118)

  - A data race flaw was found in the Linux kernel, between where con is allocated and con->sock is set. This
    issue leads to a NULL pointer dereference when accessing con->sock->sk in net/tipc/topsrv.c in the tipc
    protocol in the Linux kernel. (CVE-2023-1382)

  - Due to a vulnerability in the io_uring subsystem, it is possible to leak kernel memory information to the
    user process. timens_install calls current_is_single_threaded to determine if the current process is
    single-threaded, but this call does not consider io_uring's io_worker threads, thus it is possible to
    insert a time namespace's vvar page to process's memory space via a page fault. When this time namespace
    is destroyed, the vvar page is also freed, but not removed from the process' memory, and a next page
    allocated by the kernel will be still available from the user-space process and can leak memory contents
    via this (read-only) use-after-free vulnerability. We recommend upgrading past version 5.10.161 or commit
    788d0824269bef539fe31a785b1517882eafed93
    https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/io_uring (CVE-2023-23586)

  - In the Linux kernel before 6.1.13, there is a double free in net/mpls/af_mpls.c upon an allocation failure
    (for registering the sysctl table under a new location) during the renaming of a device. (CVE-2023-26545)

  - A NULL pointer dereference flaw was found in the UNIX protocol in net/unix/diag.c In unix_diag_get_exact
    in the Linux Kernel. The newly allocated skb does not have sk, leading to a NULL pointer. This flaw allows
    a local user to crash or potentially cause a denial of service. (CVE-2023-28327)

  - A NULL pointer dereference flaw was found in the az6027 driver in drivers/media/usb/dev-usb/az6027.c in
    the Linux Kernel. The message from user space is not checked properly before transferring into the device.
    This flaw allows a local user to crash the system or potentially cause a denial of service.
    (CVE-2023-28328)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2272
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ef310a6");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0045");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-1118");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(11)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "kernel-5.10.0-60.18.0.50.h815.eulerosv2r11",
  "kernel-abi-stablelists-5.10.0-60.18.0.50.h815.eulerosv2r11",
  "kernel-tools-5.10.0-60.18.0.50.h815.eulerosv2r11",
  "kernel-tools-libs-5.10.0-60.18.0.50.h815.eulerosv2r11",
  "python3-perf-5.10.0-60.18.0.50.h815.eulerosv2r11"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"11", reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
