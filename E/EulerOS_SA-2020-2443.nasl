#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(142576);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2019-19036",
    "CVE-2019-20811",
    "CVE-2020-0009",
    "CVE-2020-10711",
    "CVE-2020-10720",
    "CVE-2020-10732",
    "CVE-2020-10751",
    "CVE-2020-10769",
    "CVE-2020-12768",
    "CVE-2020-13974",
    "CVE-2020-15393",
    "CVE-2020-16166",
    "CVE-2020-24394",
    "CVE-2020-25211"
  );

  script_name(english:"EulerOS Virtualization 3.0.6.6 : kernel (EulerOS-SA-2020-2443)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - btrfs_root_node in fs/btrfs/ctree.c in the Linux kernel
    through 5.3.12 allows a NULL pointer dereference
    because rcu_dereference(root->node) can be
    zero.(CVE-2019-19036)

  - An issue was discovered in the Linux kernel before
    5.0.6. In rx_queue_add_kobject() and
    netdev_queue_add_kobject() in net/core/net-sysfs.c, a
    reference count is mishandled, aka
    CID-a3e23f719f5c.(CVE-2019-20811)

  - In calc_vm_may_flags of ashmem.c, there is a possible
    arbitrary write to shared memory due to a permissions
    bypass. This could lead to local escalation of
    privilege by corrupting memory shared between
    processes, with no additional execution privileges
    needed. User interaction is not needed for
    exploitation. Product: Android Versions: Android kernel
    Android ID: A-142938932(CVE-2020-0009)

  - ** DISPUTED ** An issue was discovered in the Linux
    kernel before 5.6. svm_cpu_uninit in arch/x86/kvm/svm.c
    has a memory leak, aka CID-d80b64ff297e. NOTE: third
    parties dispute this issue because it's a one-time leak
    at the boot, the size is negligible, and it can't be
    triggered at will.(CVE-2020-12768)

  - ** DISPUTED ** An issue was discovered in the Linux
    kernel through 5.7.1. drivers/tty/vt/keyboard.c has an
    integer overflow if k_ascii is called several times in
    a row, aka CID-b86dab054059. NOTE: Members in the
    community argue that the integer overflow does not lead
    to a security issue in this case.(CVE-2020-13974)

  - In the Linux kernel through 5.7.6, usbtest_disconnect
    in drivers/usb/misc/usbtest.c has a memory leak, aka
    CID-28ebeb8db770.(CVE-2020-15393)

  - A NULL pointer dereference flaw was found in the Linux
    kernel's SELinux subsystem in versions before 5.7. This
    flaw occurs while importing the Commercial IP Security
    Option (CIPSO) protocol's category bitmap into the
    SELinux extensible bitmap via the'
    ebitmap_netlbl_import' routine. While processing the
    CIPSO restricted bitmap tag in the
    'cipso_v4_parsetag_rbm' routine, it sets the security
    attribute to indicate that the category bitmap is
    present, even if it has not been allocated. This issue
    leads to a NULL pointer dereference issue while
    importing the same category bitmap into SELinux. This
    flaw allows a remote network user to crash the system
    kernel, resulting in a denial of service(
    CVE-2020-10711)

  - A flaw was found in the Linux kernel's implementation
    of Userspace core dumps. This flaw allows an attacker
    with a local account to crash a trivial program and
    exfiltrate private kernel data.(CVE-2020-10732)

  - A flaw was found in the Linux kernels SELinux LSM hook
    implementation before version 5.7, where it incorrectly
    assumed that an skb would only contain a single netlink
    message. The hook would incorrectly only validate the
    first netlink message in the skb and allow or deny the
    rest of the messages within the skb with the granted
    permission without further processing.(CVE-2020-10751)

  - A buffer over-read flaw was found in RH kernel versions
    before 5.0 in crypto_authenc_extractkeys in
    crypto/authenc.c in the IPsec Cryptographic algorithm's
    module, authenc. When a payload longer than 4 bytes,
    and is not following 4-byte alignment boundary
    guidelines, it causes a buffer over-read threat,
    leading to a system crash. This flaw allows a local
    attacker with user privileges to cause a denial of
    service.(CVE-2020-10769)

  - In the Linux kernel before 5.7.8, fs/nfsd/vfs.c (in the
    NFS server) can set incorrect permissions on new
    filesystem objects when the filesystem lacks ACL
    support, aka CID-22cf8419f131. This occurs because the
    current umask is not considered.(CVE-2020-24394)

  - The Linux kernel through 5.7.11 allows remote attackers
    to make observations that help to obtain sensitive
    information about the internal state of the network
    RNG, aka CID-f227e3ec3b5c. This is related to
    drivers/char/random.c and
    kernel/time/timer.c.(CVE-2020-16166)

  - A flaw was found in the Linux kernel's implementation
    of GRO in versions before 5.2. This flaw allows an
    attacker with local access to crash the
    system.(CVE-2020-10720)

  - In the Linux kernel through 5.8.7, local attackers able
    to inject conntrack netlink configuration could
    overflow a local buffer, causing crashes or triggering
    use of incorrect protocol numbers in
    ctnetlink_parse_tuple_filter in
    net/netfilter/nf_conntrack_netlink.c, aka
    CID-1cc5ef91d2ff.(CVE-2020-25211)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2443
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?031994d2");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.6.6") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.6");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.6_117",
        "kernel-devel-3.10.0-862.14.1.6_117",
        "kernel-headers-3.10.0-862.14.1.6_117",
        "kernel-tools-3.10.0-862.14.1.6_117",
        "kernel-tools-libs-3.10.0-862.14.1.6_117",
        "kernel-tools-libs-devel-3.10.0-862.14.1.6_117",
        "perf-3.10.0-862.14.1.6_117",
        "python-perf-3.10.0-862.14.1.6_117"];

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
