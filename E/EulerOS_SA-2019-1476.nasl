#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124800);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2013-2895",
    "CVE-2013-4516",
    "CVE-2014-7283",
    "CVE-2015-2877",
    "CVE-2015-3636",
    "CVE-2015-4003",
    "CVE-2015-4004",
    "CVE-2015-8952",
    "CVE-2015-8964",
    "CVE-2016-2061",
    "CVE-2016-3137",
    "CVE-2017-5550",
    "CVE-2017-8824",
    "CVE-2017-17806",
    "CVE-2017-18193",
    "CVE-2017-18255",
    "CVE-2018-1092",
    "CVE-2018-8822",
    "CVE-2018-12633",
    "CVE-2018-14609"
  );
  script_bugtraq_id(
    62045,
    63519,
    70261,
    74450,
    74668
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1476)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - A use-after-free vulnerability was found in DCCP socket
    code affecting the Linux kernel since 2.6.16. This
    vulnerability could allow an attacker to their escalate
    privileges.(CVE-2017-8824i1/4%0

  - The OZWPAN driver in the Linux kernel through 4.0.5
    relies on an untrusted length field during packet
    parsing, which allows remote attackers to obtain
    sensitive information from kernel memory or cause a
    denial of service (out-of-bounds read and system crash)
    via a crafted packet.(CVE-2015-4004i1/4%0

  - Integer signedness error in the MSM V4L2 video driver
    for the Linux kernel 3.x, as used in Qualcomm
    Innovation Center (QuIC) Android contributions for MSM
    devices and other products, allows attackers to gain
    privileges or cause a denial of service (array overflow
    and memory corruption) via a crafted application that
    triggers an msm_isp_axi_create_stream
    call.(CVE-2016-2061i1/4%0

  - A denial of service flaw was found in the way the Linux
    kernel's XFS file system implementation ordered
    directory hashes under certain conditions. A local
    attacker could use this flaw to corrupt the file system
    by creating directories with colliding hash values,
    potentially resulting in a system
    crash.(CVE-2014-7283i1/4%0

  - It was found that the Linux kernel's ping socket
    implementation did not properly handle socket unhashing
    during spurious disconnects, which could lead to a
    use-after-free flaw. On x86-64 architecture systems, a
    local user able to create ping sockets could use this
    flaw to crash the system. On non-x86-64 architecture
    systems, a local user able to create ping sockets could
    use this flaw to escalate their privileges on the
    system.(CVE-2015-3636i1/4%0

  - Incorrect buffer length handling was found in the
    ncp_read_kernel function in fs/ncpfs/ncplib_kernel.c in
    the Linux kernel, which could be exploited by malicious
    NCPFS servers to crash the kernel or possibly execute
    an arbitrary code.(CVE-2018-8822i1/4%0

  - ** DISPUTED ** Kernel Samepage Merging (KSM) in the
    Linux kernel 2.6.32 through 4.x does not prevent use of
    a write-timing side channel, which allows guest OS
    users to defeat the ASLR protection mechanism on other
    guest OS instances via a Cross-VM ASL INtrospection
    (CAIN) attack. NOTE: the vendor states 'Basically if
    you care about this attack vector, disable
    deduplication.' Share-until-written approaches for
    memory conservation among mutually untrusting tenants
    are inherently detectable for information disclosure,
    and can be classified as potentially misunderstood
    behaviors rather than vulnerabilities.(CVE-2015-2877i1/4%0

  - The tty_set_termios_ldisc() function in
    'drivers/tty/tty_ldisc.c' in the Linux kernel before
    4.5 allows local users to obtain sensitive information
    from kernel memory by reading a tty data
    structure.(CVE-2015-8964i1/4%0

  - An issue was discovered in the Linux kernel through
    4.17.2. vbg_misc_device_ioctl() in
    drivers/virt/vboxguest/vboxguest_linux.c reads the same
    user data twice with copy_from_user. The header part of
    the user data is double-fetched, and a malicious user
    thread can tamper with the critical variables
    (hdr.size_in and hdr.size_out) in the header between
    the two fetches because of a race condition, leading to
    severe kernel errors, such as buffer over-accesses.
    This bug can cause a local denial of service and
    information leakage.(CVE-2018-12633i1/4%0

  - ** RESERVED ** This candidate has been reserved by an
    organization or individual that will use it when
    announcing a new security problem. When the candidate
    has been publicized, the details for this candidate
    will be provided.(CVE-2018-1092i1/4%0

  - fs/f2fs/extent_cache.c in the Linux kernel, before
    4.13, mishandles extent trees. This allows local users
    to cause a denial of service via an application with
    multiple threads.(CVE-2017-18193i1/4%0

  - A design flaw was found in the file extended attribute
    handling of the Linux kernel's handling of cached
    attributes. Too many entries in the cache cause a soft
    lockup while attempting to iterate the cache and access
    relevant locks.(CVE-2015-8952i1/4%0

  - Off-by-one error in the pipe_advance function in
    lib/iov_iter.c in the Linux kernel before 4.9.5 allows
    local users to obtain sensitive information from
    uninitialized heap-memory locations in opportunistic
    circumstances by reading from a pipe after an incorrect
    buffer-release decision.(CVE-2017-5550i1/4%0

  - The HMAC implementation (crypto/hmac.c) in the Linux
    kernel, before 4.14.8, does not validate that the
    underlying cryptographic hash algorithm is unkeyed.
    This allows a local attacker, able to use the
    AF_ALG-based hash interface
    (CONFIG_CRYPTO_USER_API_HASH) and the SHA-3 hash
    algorithm (CONFIG_CRYPTO_SHA3), to cause a kernel stack
    buffer overflow by executing a crafted sequence of
    system calls that encounter a missing SHA-3
    initialization.(CVE-2017-17806i1/4%0

  - The mp_get_count function in
    drivers/staging/sb105x/sb_pci_mp.c in the Linux kernel
    before 3.12 does not initialize a certain data
    structure, which allows local users to obtain sensitive
    information from kernel stack memory via a TIOCGICOUNT
    ioctl call.(CVE-2013-4516i1/4%0

  - The perf_cpu_time_max_percent_handler function in
    kernel/events/core.c in the Linux kernel before 4.11
    allows local users to cause a denial of service
    (integer overflow) or possibly have unspecified other
    impact via a large value, as demonstrated by an
    incorrect sample-rate calculation.(CVE-2017-18255i1/4%0

  - An issue was discovered in the btrfs filesystem code in
    the Linux kernel. An invalid pointer dereference in
    __del_reloc_root() in fs/btrfs/relocation.c when
    mounting a crafted btrfs image could lead to a system
    crash and a denial of service.(CVE-2018-14609i1/4%0

  - The oz_usb_handle_ep_data function in
    drivers/staging/ozwpan/ozusbsvc1.c in the OZWPAN driver
    in the Linux kernel through 4.0.5 allows remote
    attackers to cause a denial of service (divide-by-zero
    error and system crash) via a crafted
    packet.(CVE-2015-4003i1/4%0

  - drivers/hid/hid-logitech-dj.c in the Human Interface
    Device (HID) subsystem in the Linux kernel through
    3.11, when CONFIG_HID_LOGITECH_DJ is enabled, allows
    physically proximate attackers to cause a denial of
    service (NULL pointer dereference and OOPS) or obtain
    sensitive information from kernel memory via a crafted
    device.(CVE-2013-2895i1/4%0

  - drivers/usb/serial/cypress_m8.c in the Linux kernel
    before 4.5.1 allows physically proximate attackers to
    cause a denial of service (NULL pointer dereference and
    system crash) via a USB device without both an
    interrupt-in and an interrupt-out endpoint descriptor,
    related to the cypress_generic_port_probe and
    cypress_open functions.(CVE-2016-3137i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1476
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0934af5b");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4004");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-8822");

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
