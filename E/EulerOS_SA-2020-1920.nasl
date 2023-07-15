#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(140141);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2019-19039",
    "CVE-2019-20810",
    "CVE-2019-20811",
    "CVE-2020-0009",
    "CVE-2020-10711",
    "CVE-2020-10732",
    "CVE-2020-10751",
    "CVE-2020-12770",
    "CVE-2020-12826",
    "CVE-2020-13143"
  );

  script_name(english:"EulerOS 2.0 SP5 : kernel (EulerOS-SA-2020-1920)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - In calc_vm_may_flags of ashmem.c, there is a possible
    arbitrary write to shared memory due to a permissions
    bypass. This could lead to local escalation of
    privilege by corrupting memory shared between
    processes, with no additional execution privileges
    needed. User interaction is not needed for
    exploitation. Product: Android Versions: Android kernel
    Android ID: A-142938932(CVE-2020-0009)

  - A flaw was found in the Linux kernel's implementation
    of Userspace core dumps. This flaw allows an attacker
    with a local account to crash a trivial program and
    exfiltrate private kernel data.(CVE-2020-10732)

  - An issue was discovered in the Linux kernel before
    5.0.6. In rx_queue_add_kobject() and
    netdev_queue_add_kobject() in net/core/net-sysfs.c, a
    reference count is mishandled, aka
    CID-a3e23f719f5c.(CVE-2019-20811)

  - go7007_snd_init in
    drivers/media/usb/go7007/snd-go7007.c in the Linux
    kernel before 5.6 does not call snd_card_free for a
    failure path, which causes a memory leak, aka
    CID-9453264ef586.(CVE-2019-20810)

  - A flaw was found in the Linux kernels SELinux LSM hook
    implementation before version 5.7, where it incorrectly
    assumed that an skb would only contain a single netlink
    message. The hook would incorrectly only validate the
    first netlink message in the skb and allow or deny the
    rest of the messages within the skb with the granted
    permission without further processing.(CVE-2020-10751)

  - A signal access-control issue was discovered in the
    Linux kernel before 5.6.5, aka CID-7395ea4e65c2.
    Because exec_id in include/linux/sched.h is only 32
    bits, an integer overflow can interfere with a
    do_notify_parent protection mechanism. A child process
    can send an arbitrary signal to a parent process in a
    different security domain. Exploitation limitations
    include the amount of elapsed time before an integer
    overflow occurs, and the lack of scenarios where
    signals to a parent process present a substantial
    operational threat.(CVE-2020-12826)

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
    kernel, resulting in a denial of
    service.(CVE-2020-10711)

  - gadget_dev_desc_UDC_store in
    drivers/usb/gadget/configfs.c in the Linux kernel
    through 5.6.13 relies on kstrdup without considering
    the possibility of an internal '\0' value, which allows
    attackers to trigger an out-of-bounds read, aka
    CID-15753588bcd4.(CVE-2020-13143)

  - An issue was discovered in the Linux kernel through
    5.6.11. sg_write lacks an sg_remove_request call in a
    certain failure case, aka
    CID-83c6f2390040.(CVE-2020-12770)

  - __btrfs_free_extent in fs/btrfs/extent-tree.c in the
    Linux kernel through 5.3.12 calls btrfs_print_leaf in a
    certain ENOENT case, which allows local users to obtain
    potentially sensitive information about register values
    via the dmesg program. NOTE: The BTRFS development team
    disputes this issues as not being a vulnerability
    because '1) The kernel provide facilities to restrict
    access to dmesg - dmesg_restrict=1 sysctl option. So
    it's really up to the system administrator to judge
    whether dmesg access shall be disallowed or not. 2)
    WARN/WARN_ON are widely used macros in the linux
    kernel. If this CVE is considered valid this would mean
    there are literally thousands CVE lurking in the kernel
    - something which clearly is not the
    case.'(CVE-2019-19039)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1920
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3e29a06");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12770");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
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

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.5.h458.eulerosv2r7",
        "kernel-devel-3.10.0-862.14.1.5.h458.eulerosv2r7",
        "kernel-headers-3.10.0-862.14.1.5.h458.eulerosv2r7",
        "kernel-tools-3.10.0-862.14.1.5.h458.eulerosv2r7",
        "kernel-tools-libs-3.10.0-862.14.1.5.h458.eulerosv2r7",
        "perf-3.10.0-862.14.1.5.h458.eulerosv2r7",
        "python-perf-3.10.0-862.14.1.5.h458.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
