#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0021. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134312);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id(
    "CVE-2017-17805",
    "CVE-2018-9568",
    "CVE-2018-12207",
    "CVE-2018-17972",
    "CVE-2019-0154",
    "CVE-2019-0155",
    "CVE-2019-1125",
    "CVE-2019-3900",
    "CVE-2019-5489",
    "CVE-2019-11135",
    "CVE-2019-11810",
    "CVE-2019-14821"
  );
  script_bugtraq_id(
    102291,
    105525,
    106129,
    106478,
    108076,
    108286
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"NewStart CGSL MAIN 4.05 : kernel Multiple Vulnerabilities (NS-SA-2020-0021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has kernel packages installed that are affected by multiple
vulnerabilities:

  - The Salsa20 encryption algorithm in the Linux kernel
    before 4.14.8 does not correctly handle zero-length
    inputs, allowing a local attacker able to use the
    AF_ALG-based skcipher interface
    (CONFIG_CRYPTO_USER_API_SKCIPHER) to cause a denial of
    service (uninitialized-memory free and kernel crash) or
    have unspecified other impact by executing a crafted
    sequence of system calls that use the blkcipher_walk
    API. Both the generic implementation
    (crypto/salsa20_generic.c) and x86 implementation
    (arch/x86/crypto/salsa20_glue.c) of Salsa20 were
    vulnerable. (CVE-2017-17805)

  - Improper invalidation for page table updates by a
    virtual guest operating system for multiple Intel(R)
    Processors may allow an authenticated user to
    potentially enable denial of service of the host system
    via local access. (CVE-2018-12207)

  - An issue was discovered in the proc_pid_stack function
    in fs/proc/base.c in the Linux kernel through 4.18.11.
    It does not ensure that only root may inspect the kernel
    stack of an arbitrary task, allowing a local attacker to
    exploit racy stack unwinding and leak kernel task stack
    contents. (CVE-2018-17972)

  - In sk_clone_lock of sock.c, there is a possible memory
    corruption due to type confusion. This could lead to
    local escalation of privilege with no additional
    execution privileges needed. User interaction is not
    needed for exploitation. Product: Android. Versions:
    Android kernel. Android ID: A-113509306. References:
    Upstream kernel. (CVE-2018-9568)

  - Insufficient access control in subsystem for Intel (R)
    processor graphics in 6th, 7th, 8th and 9th Generation
    Intel(R) Core(TM) Processor Families; Intel(R)
    Pentium(R) Processor J, N, Silver and Gold Series;
    Intel(R) Celeron(R) Processor J, N, G3900 and G4900
    Series; Intel(R) Atom(R) Processor A and E3900 Series;
    Intel(R) Xeon(R) Processor E3-1500 v5 and v6 and E-2100
    Processor Families may allow an authenticated user to
    potentially enable denial of service via local access.
    (CVE-2019-0154)

  - Insufficient access control in a subsystem for Intel (R)
    processor graphics in 6th, 7th, 8th and 9th Generation
    Intel(R) Core(TM) Processor Families; Intel(R)
    Pentium(R) Processor J, N, Silver and Gold Series;
    Intel(R) Celeron(R) Processor J, N, G3900 and G4900
    Series; Intel(R) Atom(R) Processor A and E3900 Series;
    Intel(R) Xeon(R) Processor E3-1500 v5 and v6, E-2100 and
    E-2200 Processor Families; Intel(R) Graphics Driver for
    Windows before 26.20.100.6813 (DCH) or 26.20.100.6812
    and before 21.20.x.5077 (aka15.45.5077), i915 Linux
    Driver for Intel(R) Processor Graphics before versions
    5.4-rc7, 5.3.11, 4.19.84, 4.14.154, 4.9.201, 4.4.201 may
    allow an authenticated user to potentially enable
    escalation of privilege via local access.
    (CVE-2019-0155)

  - TSX Asynchronous Abort condition on some CPUs utilizing
    speculative execution may allow an authenticated user to
    potentially enable information disclosure via a side
    channel with local access. (CVE-2019-11135)

  - An information disclosure vulnerability exists when
    certain central processing units (CPU) speculatively
    access memory, aka 'Windows Kernel Information
    Disclosure Vulnerability'. This CVE ID is unique from
    CVE-2019-1071, CVE-2019-1073. (CVE-2019-1125)

  - An issue was discovered in the Linux kernel before
    5.0.7. A NULL pointer dereference can occur when
    megasas_create_frame_pool() fails in
    megasas_alloc_cmds() in
    drivers/scsi/megaraid/megaraid_sas_base.c. This causes a
    Denial of Service, related to a use-after-free.
    (CVE-2019-11810)

  - An out-of-bounds access issue was found in the Linux
    kernel, all versions through 5.3, in the way Linux
    kernel's KVM hypervisor implements the Coalesced MMIO
    write operation. It operates on an MMIO ring buffer
    'struct kvm_coalesced_mmio' object, wherein write
    indices 'ring->first' and 'ring->last' value could be
    supplied by a host user-space process. An unprivileged
    host user or process with access to '/dev/kvm' device
    could use this flaw to crash the host kernel, resulting
    in a denial of service or potentially escalating
    privileges on the system. (CVE-2019-14821)

  - An infinite loop issue was found in the vhost_net kernel
    module in Linux Kernel up to and including v5.1-rc6,
    while handling incoming packets in handle_rx(). It could
    occur if one end sends packets faster than the other end
    can process them. A guest user, maybe remote one, could
    use this flaw to stall the vhost_net kernel thread,
    resulting in a DoS scenario. (CVE-2019-3900)

  - The mincore() implementation in mm/mincore.c in the
    Linux kernel through 4.19.13 allowed local attackers to
    observe page cache access patterns of other processes on
    the same system, potentially allowing sniffing of secret
    information. (Fixing this affects the output of the
    fincore program.) Limited remote exploitation may be
    possible, as demonstrated by latency differences in
    accessing public files from an Apache HTTP Server.
    (CVE-2019-5489)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0021");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14821");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL MAIN 4.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.05": [
    "kernel-2.6.32-642.13.1.el6.cgslv4_5.0.149.g46fdcf6",
    "kernel-abi-whitelists-2.6.32-642.13.1.el6.cgslv4_5.0.149.g46fdcf6",
    "kernel-debug-2.6.32-642.13.1.el6.cgslv4_5.0.149.g46fdcf6",
    "kernel-debug-debuginfo-2.6.32-642.13.1.el6.cgslv4_5.0.149.g46fdcf6",
    "kernel-debug-devel-2.6.32-642.13.1.el6.cgslv4_5.0.149.g46fdcf6",
    "kernel-debuginfo-2.6.32-642.13.1.el6.cgslv4_5.0.149.g46fdcf6",
    "kernel-debuginfo-common-x86_64-2.6.32-642.13.1.el6.cgslv4_5.0.149.g46fdcf6",
    "kernel-devel-2.6.32-642.13.1.el6.cgslv4_5.0.149.g46fdcf6",
    "kernel-firmware-2.6.32-642.13.1.el6.cgslv4_5.0.149.g46fdcf6",
    "kernel-headers-2.6.32-642.13.1.el6.cgslv4_5.0.149.g46fdcf6",
    "perf-2.6.32-642.13.1.el6.cgslv4_5.0.149.g46fdcf6",
    "perf-debuginfo-2.6.32-642.13.1.el6.cgslv4_5.0.149.g46fdcf6",
    "python-perf-2.6.32-642.13.1.el6.cgslv4_5.0.149.g46fdcf6",
    "python-perf-debuginfo-2.6.32-642.13.1.el6.cgslv4_5.0.149.g46fdcf6"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
