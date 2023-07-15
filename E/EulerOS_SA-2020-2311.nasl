#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(142148);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2015-7837",
    "CVE-2020-0432",
    "CVE-2020-12351",
    "CVE-2020-12352",
    "CVE-2020-14314",
    "CVE-2020-14331",
    "CVE-2020-14351",
    "CVE-2020-14386",
    "CVE-2020-24490",
    "CVE-2020-25285",
    "CVE-2020-25641",
    "CVE-2020-25643",
    "CVE-2020-25645",
    "CVE-2020-26088"
  );

  script_name(english:"EulerOS 2.0 SP8 : kernel (EulerOS-SA-2020-2311)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The kernel package contains the Linux kernel (vmlinuz),
    the core of any Linux operating system. The kernel
    handles the basic functions of the operating system:
    memory allocation, process allocation, device input and
    output, etc.Security Fix(es):An information leak flaw
    was found in the way the Linux kernel's Bluetooth stack
    implementation handled initialization of stack memory
    when handling certain AMP packets. A remote attacker in
    adjacent range could use this flaw to leak small
    portions of stack memory on the system by sending a
    specially crafted AMP packets. The highest threat from
    this vulnerability is to data
    confidentiality.(CVE-2020-12352)A flaw was found in the
    way the Linux kernel Bluetooth implementation handled
    L2CAP packets with A2MP CID. A remote attacker in
    adjacent range could use this flaw to crash the system
    causing denial of service or potentially execute
    arbitrary code on the system by sending a specially
    crafted L2CAP packet. The highest threat from this
    vulnerability is to data confidentiality and integrity
    as well as system availability.(CVE-2020-12351)A heap
    buffer overflow flaw was found in the way the Linux
    kernel's Bluetooth implementation processed extended
    advertising report events. This flaw allows a remote
    attacker in an adjacent range to crash the system,
    causing a denial of service or to potentially execute
    arbitrary code on the system by sending a specially
    crafted Bluetooth packet. The highest threat from this
    vulnerability is to confidentiality, integrity, as well
    as system availability.(CVE-2020-24490)A flaw was found
    in the Linux kernel in versions before 5.9-rc7. Traffic
    between two Geneve endpoints may be unencrypted when
    IPsec is configured to encrypt traffic for the specific
    UDP port used by the GENEVE tunnel allowing anyone
    between the two endpoints to read the traffic
    unencrypted. The main threat from this vulnerability is
    to data confidentiality.(CVE-2020-25645)A flaw was
    found in the Linux kernel's implementation of the
    invert video code on VGA consoles when a local attacker
    attempts to resize the console, calling an ioctl
    VT_RESIZE, which causes an out-of-bounds write to
    occur. This flaw allows a local user with access to the
    VGA console to crash the system, potentially escalating
    their privileges on the system. The highest threat from
    this vulnerability is to data confidentiality and
    integrity as well as system
    availability.(CVE-2020-14331)A missing CAP_NET_RAW
    check in NFC socket creation in netfc/rawsock.c in the
    Linux kernel before 5.8.2 could be used by local
    attackers to create raw sockets, bypassing security
    mechanisms, aka CID-26896f01467a.(CVE-2020-26088)perf:
    Fix race in perf_mmap_close function(CVE-2020-14351)A
    flaw was found in the Linux kernel before 5.9-rc4.
    Memory corruption can be exploited to gain root
    privileges from unprivileged processes. The highest
    threat from this vulnerability is to data
    confidentiality and integrity.(CVE-2020-14386)A flaw
    was found in the HDLC_PPP module of the Linux kernel in
    versions before 5.9-rc7. Memory corruption and a read
    overflow is caused by improper input validation in the
    ppp_cp_parse_cr function which can cause the system to
    crash or cause a denial of service. The highest threat
    from this vulnerability is to data confidentiality and
    integrity as well as system
    availability.(CVE-2020-25643)The Linux kernel, as used
    in Red Hat Enterprise Linux 7, kernel-rt, and
    Enterprise MRG 2 and when booted with UEFI Secure Boot
    enabled, allows local users to bypass intended
    securelevel/secureboot restrictions by leveraging
    improper handling of secure_boot flag across kexec
    reboot.(CVE-2015-7837)A flaw was found in the Linux
    kernel's implementation of biovecs in versions before
    5.9-rc7. A zero-length biovec request issued by the
    block subsystem could cause the kernel to enter an
    infinite loop, causing a denial of service. This flaw
    allows a local attacker with basic privileges to issue
    requests to a block device, resulting in a denial of
    service. The highest threat from this vulnerability is
    to system availability.(CVE-2020-25641)A memory
    out-of-bounds read flaw was found in the Linux kernel
    before 5.9-rc2 with the ext3/ext4 file system, in the
    way it accesses a directory with broken indexing. This
    flaw allows a local user to crash the system if the
    directory exists. The highest threat from this
    vulnerability is to system
    availability.(CVE-2020-14314)In skb_to_mamac of
    networking.c, there is a possible out of bounds write
    due to an integer overflow. This could lead to local
    escalation of privilege with no additional execution
    privileges needed. User interaction is not needed for
    exploitation.Product: AndroidVersions: Android
    kernelAndroid ID:
    A-143560807(CVE-2020-0432)get_gate_page in mm/gup.c in
    the Linux kernel 5.7.x and 5.8.x before 5.8.7 allows
    privilege escalation because of incorrect reference
    counting (caused by gate page mishandling) of the
    struct page that backs the vsyscall page. The result is
    a refcount underflow. This can be triggered by any
    64-bit process that can use ptrace() or
    process_vm_readv(), aka
    CID-9fa2dd946743.(CVE-2020-25285)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2311
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d2e51dd");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25643");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-12351");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["bpftool-4.19.36-vhulk1907.1.0.h874.eulerosv2r8",
        "kernel-4.19.36-vhulk1907.1.0.h874.eulerosv2r8",
        "kernel-devel-4.19.36-vhulk1907.1.0.h874.eulerosv2r8",
        "kernel-headers-4.19.36-vhulk1907.1.0.h874.eulerosv2r8",
        "kernel-source-4.19.36-vhulk1907.1.0.h874.eulerosv2r8",
        "kernel-tools-4.19.36-vhulk1907.1.0.h874.eulerosv2r8",
        "kernel-tools-libs-4.19.36-vhulk1907.1.0.h874.eulerosv2r8",
        "perf-4.19.36-vhulk1907.1.0.h874.eulerosv2r8",
        "python-perf-4.19.36-vhulk1907.1.0.h874.eulerosv2r8",
        "python3-perf-4.19.36-vhulk1907.1.0.h874.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
