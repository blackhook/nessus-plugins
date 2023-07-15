#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104296);
  script_version("3.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-1000111",
    "CVE-2017-1000112",
    "CVE-2017-12188",
    "CVE-2017-12192",
    "CVE-2017-14991",
    "CVE-2017-15265",
    "CVE-2017-15274",
    "CVE-2017-15649"
  );

  script_name(english:"EulerOS 2.0 SP1 : kernel (EulerOS-SA-2017-1271)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - arch/x86/kvm/mmu.c in the Linux kernel through 4.13.5,
    when nested virtualisation is used, does not properly
    traverse guest pagetable entries to resolve a guest
    virtual address, which allows L1 guest OS users to
    execute arbitrary code on the host OS or cause a denial
    of service (incorrect index during page walking, and
    host OS crash), aka an MMU potential stack buffer
    overrun.(CVE-2017-12188)

  - A vulnerability was found in the Key Management sub
    component of the Linux kernel, where when trying to
    issue a KEYTCL_READ on negative key would lead to a
    NULL pointer dereference. A local attacker could use
    this flaw to crash the kernel.(CVE-2017-12192)

  - security/keys/keyctl.c in the Linux kernel before
    4.11.5 does not consider the case of a NULL payload in
    conjunction with a nonzero length value, which allows
    local users to cause a denial of service (NULL pointer
    dereference and OOPS) via a crafted add_key or keyctl
    system call, a different vulnerability than
    CVE-2017-12192.(CVE-2017-15274)

  - Linux kernel: heap out-of-bounds in AF_PACKET sockets.
    This new issue is analogous to previously disclosed
    CVE-2016-8655. In both cases, a socket option that
    changes socket state may race with safety checks in
    packet_set_ring. Previously with PACKET_VERSION. This
    time with PACKET_RESERVE. The solution is similar: lock
    the socket for the update. This issue may be
    exploitable, we did not investigate further. As this
    issue affects PF_PACKET sockets, it requires
    CAP_NET_RAW in the process namespace. But note that
    with user namespaces enabled, any process can create a
    namespace in which it has
    CAP_NET_RAW.(CVE-2017-1000111)

  - Use-after-free vulnerability in the Linux kernel before
    4.14-rc5 allows local users to have unspecified impact
    via vectors related to /dev/snd/seq.(CVE-2017-15265)

  - net/packet/af_packet.c in the Linux kernel before
    4.13.6 allows local users to gain privileges via
    crafted system calls that trigger mishandling of
    packet_fanout data structures, because of a race
    condition (involving fanout_add and packet_do_bind)
    that leads to a use-after-free, a different
    vulnerability than CVE-2017-6346.(CVE-2017-15649)

  - The sg_ioctl function in drivers/scsi/sg.c in the Linux
    kernel before 4.13.4 allows local users to obtain
    sensitive information from uninitialized kernel
    heap-memory locations via an SG_GET_REQUEST_TABLE ioctl
    call for /dev/sg0.(CVE-2017-14991)

  - An exploitable memory corruption flaw was found in the
    Linux kernel. The append path can be erroneously
    switched from UFO to non-UFO in ip_ufo_append_data()
    when building an UFO packet with MSG_MORE option. If
    unprivileged user namespaces are available, this flaw
    can be exploited to gain root
    privileges.(CVE-2017-1000112)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1271
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d973af9c");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel UDP Fragmentation Offset (UFO) Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debug");
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

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-229.49.1.152",
        "kernel-debug-3.10.0-229.49.1.152",
        "kernel-debuginfo-3.10.0-229.49.1.152",
        "kernel-debuginfo-common-x86_64-3.10.0-229.49.1.152",
        "kernel-devel-3.10.0-229.49.1.152",
        "kernel-headers-3.10.0-229.49.1.152",
        "kernel-tools-3.10.0-229.49.1.152",
        "kernel-tools-libs-3.10.0-229.49.1.152",
        "perf-3.10.0-229.49.1.152",
        "python-perf-3.10.0-229.49.1.152"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

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
