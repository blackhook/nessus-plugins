#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125301);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2013-4513",
    "CVE-2013-4587",
    "CVE-2014-1737",
    "CVE-2014-3631",
    "CVE-2014-4655",
    "CVE-2014-9419",
    "CVE-2015-1420",
    "CVE-2015-5257",
    "CVE-2015-7515",
    "CVE-2015-8575",
    "CVE-2015-8961",
    "CVE-2016-4578",
    "CVE-2016-5243",
    "CVE-2016-5343",
    "CVE-2016-7917",
    "CVE-2016-9794",
    "CVE-2017-2618",
    "CVE-2017-6345",
    "CVE-2017-1000364",
    "CVE-2018-14616"
  );
  script_bugtraq_id(
    63508,
    64328,
    67300,
    68162,
    70095,
    71794,
    72357
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1508)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - drivers/soc/qcom/qdsp6v2/voice_svc.c in the QDSP6v2
    Voice Service driver for the Linux kernel 3.x, as used
    in Qualcomm Innovation Center (QuIC) Android
    contributions for MSM devices and other products,
    allows attackers to cause a denial of service (memory
    corruption) or possibly have unspecified other impact
    via a write request, as demonstrated by a
    voice_svc_send_req buffer overflow.(CVE-2016-5343i1/4%0

  - A use-after-free flaw was found in the way the Linux
    kernel's Advanced Linux Sound Architecture (ALSA)
    implementation handled user controls. A local,
    privileged user could use this flaw to crash the
    system.(CVE-2014-4655i1/4%0

  - Race condition in the handle_to_path function in
    fs/fhandle.c in the Linux kernel through 3.19.1 allows
    local users to bypass intended size restrictions and
    trigger read operations on additional memory locations
    by changing the handle_bytes value of a file handle
    during the execution of this function.(CVE-2015-1420i1/4%0

  - A flaw was found in the way the Linux kernel's keys
    subsystem handled the termination condition in the
    associative array garbage collection functionality. A
    local, unprivileged user could use this flaw to crash
    the system.(CVE-2014-3631i1/4%0

  - A flaw was found in the ext4 subsystem. This
    vulnerability is a use after free vulnerability was
    found in __ext4_journal_stop(). Attackers could abuse
    this to allow any code which attempts to deal with the
    journal failure to be mishandled or not fail at all.
    This could lead to data corruption or
    crashes.(CVE-2015-8961i1/4%0

  - Buffer overflow in the oz_cdev_write function in
    drivers/staging/ozwpan/ozcdev.c in the Linux kernel
    before 3.12 allows local users to cause a denial of
    service or possibly have unspecified other impact via a
    crafted write operation.(CVE-2013-4513i1/4%0

  - The nfnetlink_rcv_batch() function in
    'net/netfilter/nfnetlink.c' in the Linux kernel before
    4.5 does not check whether a batch message's length
    field is large enough, which allows local users to
    obtain sensitive information from kernel memory or
    cause a denial of service (infinite loop or
    out-of-bounds read) by leveraging the CAP_NET_ADMIN
    capability.(CVE-2016-7917i1/4%0

  - Array index error in the kvm_vm_ioctl_create_vcpu
    function in virt/kvm/kvm_main.c in the KVM subsystem in
    the Linux kernel through 3.12.5 allows local users to
    gain privileges via a large id value.(CVE-2013-4587i1/4%0

  - A leak of information was possible when issuing a
    netlink command of the stack memory area leading up to
    this function call. An attacker could use this to
    determine stack information for use in a later
    exploit.(CVE-2016-5243i1/4%0

  - An issue was discovered in the Linux kernel in the F2FS
    filesystem code. A NULL pointer dereference in
    fscrypt_do_page_crypto() in the fs/crypto/crypto.c
    function can occur when operating on a file on a
    corrupted f2fs image.(CVE-2018-14616i1/4%0

  - An out-of-bounds flaw was found in the kernel, where
    the sco_sock_bind() function (bluetooth/sco) did not
    check the length of its sockaddr parameter. As a
    result, more kernel memory was copied out than
    required, leaking information from the kernel stack
    (including kernel addresses). A local user could
    exploit this flaw to bypass kernel ASLR or leak other
    information.(CVE-2015-8575i1/4%0

  - A denial of service vulnerability was found in the
    WhiteHEAT USB Serial Driver (whiteheat_attach function
    in drivers/usb/serial/whiteheat.c). In the driver, the
    COMMAND_PORT variable was hard coded and set to 4 (5th
    element). The driver assumed that the number of ports
    would always be 5 and used port number 5 as the command
    port. However, when using a USB device in which the
    number of ports was set to a number less than 5 (for
    example, 3), the driver triggered a kernel NULL-pointer
    dereference. A non-privileged attacker could use this
    flaw to panic the host.(CVE-2015-5257i1/4%0

  - The LLC subsystem in the Linux kernel does not ensure
    that a certain destructor exists in required
    circumstances, which allows local users to cause a
    denial of service (BUG_ON) or possibly have unspecified
    other impact via crafted system calls.(CVE-2017-6345i1/4%0

  - A vulnerability was found in Linux kernel. There is an
    information leak in file sound/core/timer.c of the
    latest mainline Linux kernel. The stack object aEURoer1aEUR
    has a total size of 32 bytes. Its field aEURoeeventaEUR and
    aEURoevalaEUR both contain 4 bytes padding. These 8 bytes
    padding bytes are sent to user without being
    initialized.(CVE-2016-4578i1/4%0

  - An information leak flaw was found in the way the Linux
    kernel changed certain segment registers and
    thread-local storage (TLS) during a context switch. A
    local, unprivileged user could use this flaw to leak
    the user space TLS base address of an arbitrary
    process.(CVE-2014-9419i1/4%0

  - A flaw was found in the way memory was being allocated
    on the stack for user space binaries. If heap (or
    different memory region) and stack memory regions were
    adjacent to each other, an attacker could use this flaw
    to jump over the stack guard gap, cause controlled
    memory corruption on process stack or the adjacent
    memory region, and thus increase their privileges on
    the system. This is a kernel-side mitigation which
    increases the stack guard gap size from one page to 1
    MiB to make successful exploitation of this issue more
    difficult.(CVE-2017-1000364i1/4%0

  - A flaw was found in the Linux kernel's handling of
    clearing SELinux attributes on /proc/pid/attr files. An
    empty (null) write to this file can crash the system by
    causing the system to attempt to access unmapped kernel
    memory.(CVE-2017-2618i1/4%0

  - A use-after-free vulnerability was found in ALSA pcm
    layer, which allows local users to cause a denial of
    service, memory corruption, or possibly other
    unspecified impact. Due to the nature of the flaw,
    privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.(CVE-2016-9794i1/4%0

  - A flaw was found in the way the Linux kernel's floppy
    driver handled user space provided data in certain
    error code paths while processing FDRAWCMD IOCTL
    commands. A local user with write access to /dev/fdX
    could use this flaw to free (using the kfree()
    function) arbitrary kernel memory. (CVE-2014-1737,
    Important)t was found that the Linux kernel's floppy
    driver leaked internal kernel memory addresses to user
    space during the processing of the FDRAWCMD IOCTL
    command. A local user with write access to /dev/fdX
    could use this flaw to obtain information about the
    kernel heap arrangement. (CVE-2014-1738, Low)Note: A
    local user with write access to /dev/fdX could use
    these two flaws (CVE-2014-1737 in combination with
    CVE-2014-1738) to escalate their privileges on the
    system.(CVE-2014-1737i1/4%0

  - An out-of-bounds memory access flaw was found in the
    Linux kernel's aiptek USB tablet driver (aiptek_probe()
    function in drivers/input/tablet/aiptek.c). The driver
    assumed that the interface always had at least one
    endpoint. By using a specially crafted USB device with
    no endpoints on one of its interfaces, an unprivileged
    user with physical access to the system could trigger a
    kernel NULL pointer dereference, causing the system to
    panic.(CVE-2015-7515i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1508
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16ed611a");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8961");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-5343");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Solaris RSH Stack Clash Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/21");

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
