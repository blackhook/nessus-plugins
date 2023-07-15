#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0049. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127233);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2016-8633",
    "CVE-2017-5715",
    "CVE-2017-5753",
    "CVE-2017-5754",
    "CVE-2017-8824",
    "CVE-2017-13166",
    "CVE-2017-18344",
    "CVE-2017-1000365",
    "CVE-2018-3639",
    "CVE-2018-3693",
    "CVE-2018-5390",
    "CVE-2018-5391",
    "CVE-2018-8781",
    "CVE-2018-10902",
    "CVE-2018-13405",
    "CVE-2018-14634"
  );
  script_bugtraq_id(102371, 102378, 106128, 104976, 106503, 105407);

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : kernel-rt Multiple Vulnerabilities (NS-SA-2019-0049)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has kernel-rt packages installed that are affected
by multiple vulnerabilities:

  - A buffer overflow vulnerability due to a lack of input
    filtering of incoming fragmented datagrams was found in
    the IP-over-1394 driver [firewire-net] in a fragment
    handling code in the Linux kernel. The vulnerability
    exists since firewire supported IPv4, i.e. since version
    2.6.31 (year 2009) till version v4.9-rc4. A maliciously
    formed fragment with a respectively large datagram
    offset would cause a memcpy() past the datagram buffer,
    which would cause a system panic or possible arbitrary
    code execution. The flaw requires [firewire-net] module
    to be loaded and is remotely exploitable from connected
    firewire devices, but not over a local network.
    (CVE-2016-8633)

  - The Linux Kernel imposes a size restriction on the
    arguments and environmental strings passed through
    RLIMIT_STACK/RLIMIT_INFINITY, but does not take the
    argument and environment pointers into account, which
    allows attackers to bypass this limitation.
    (CVE-2017-1000365)

  - A bug in the 32-bit compatibility layer of the ioctl
    handling code of the v4l2 video driver in the Linux
    kernel has been found. A memory protection mechanism
    ensuring that user-provided buffers always point to a
    userspace memory were disabled, allowing destination
    address to be in a kernel space. This flaw could be
    exploited by an attacker to overwrite a kernel memory
    from an unprivileged userspace process, leading to
    privilege escalation. (CVE-2017-13166)

  - The timer_create syscall implementation in
    kernel/time/posix-timers.c in the Linux kernel doesn't
    properly validate the sigevent->sigev_notify field,
    which leads to out-of-bounds access in the show_timer
    function. (CVE-2017-18344)

  - An industry-wide issue was found in the way many modern
    microprocessor designs have implemented speculative
    execution of instructions (a commonly used performance
    optimization). There are three primary variants of the
    issue which differ in the way the speculative execution
    can be exploited. Variant CVE-2017-5715 triggers the
    speculative execution by utilizing branch target
    injection. It relies on the presence of a precisely-
    defined instruction sequence in the privileged code as
    well as the fact that memory accesses may cause
    allocation into the microprocessor's data cache even for
    speculatively executed instructions that never actually
    commit (retire). As a result, an unprivileged attacker
    could use this flaw to cross the syscall and guest/host
    boundaries and read privileged memory by conducting
    targeted cache side-channel attacks. (CVE-2017-5715)

  - An industry-wide issue was found in the way many modern
    microprocessor designs have implemented speculative
    execution of instructions (a commonly used performance
    optimization). There are three primary variants of the
    issue which differ in the way the speculative execution
    can be exploited. Variant CVE-2017-5753 triggers the
    speculative execution by performing a bounds-check
    bypass. It relies on the presence of a precisely-defined
    instruction sequence in the privileged code as well as
    the fact that memory accesses may cause allocation into
    the microprocessor's data cache even for speculatively
    executed instructions that never actually commit
    (retire). As a result, an unprivileged attacker could
    use this flaw to cross the syscall boundary and read
    privileged memory by conducting targeted cache side-
    channel attacks. (CVE-2017-5753)

  - An industry-wide issue was found in the way many modern
    microprocessor designs have implemented speculative
    execution of instructions (a commonly used performance
    optimization). There are three primary variants of the
    issue which differ in the way the speculative execution
    can be exploited. Variant CVE-2017-5754 relies on the
    fact that, on impacted microprocessors, during
    speculative execution of instruction permission faults,
    exception generation triggered by a faulting access is
    suppressed until the retirement of the whole instruction
    block. In a combination with the fact that memory
    accesses may populate the cache even when the block is
    being dropped and never committed (executed), an
    unprivileged local attacker could use this flaw to read
    privileged (kernel space) memory by conducting targeted
    cache side-channel attacks. Note: CVE-2017-5754 affects
    Intel x86-64 microprocessors. AMD x86-64 microprocessors
    are not affected by this issue. (CVE-2017-5754)

  - A use-after-free vulnerability was found in DCCP socket
    code affecting the Linux kernel since 2.6.16. This
    vulnerability could allow an attacker to their escalate
    privileges. (CVE-2017-8824)

  - It was found that the raw midi kernel driver does not
    protect against concurrent access which leads to a
    double realloc (double free) in
    snd_rawmidi_input_params() and
    snd_rawmidi_output_status() which are part of
    snd_rawmidi_ioctl() handler in rawmidi.c file. A
    malicious local attacker could possibly use this for
    privilege escalation. (CVE-2018-10902)

  - A vulnerability was found in the
    fs/inode.c:inode_init_owner() function logic of the
    LInux kernel that allows local users to create files
    with an unintended group ownership and with group
    execution and SGID permission bits set, in a scenario
    where a directory is SGID and belongs to a certain group
    and is writable by a user who is not a member of this
    group. This can lead to excessive permissions granted in
    case when they should not. (CVE-2018-13405)

  - An integer overflow flaw was found in the Linux kernel's
    create_elf_tables() function. An unprivileged local user
    with access to SUID (or otherwise privileged) binary
    could use this flaw to escalate their privileges on the
    system. (CVE-2018-14634)

  - An industry-wide issue was found in the way many modern
    microprocessor designs have implemented speculative
    execution of Load & Store instructions (a commonly used
    performance optimization). It relies on the presence of
    a precisely-defined instruction sequence in the
    privileged code as well as the fact that memory read
    from address to which a recent memory write has occurred
    may see an older value and subsequently cause an update
    into the microprocessor's data cache even for
    speculatively executed instructions that never actually
    commit (retire). As a result, an unprivileged attacker
    could use this flaw to read privileged memory by
    conducting targeted cache side-channel attacks.
    (CVE-2018-3639)

  - An industry-wide issue was found in the way many modern
    microprocessor designs have implemented speculative
    execution of instructions past bounds check. The flaw
    relies on the presence of a precisely-defined
    instruction sequence in the privileged code and the fact
    that memory writes occur to an address which depends on
    the untrusted value. Such writes cause an update into
    the microprocessor's data cache even for speculatively
    executed instructions that never actually commit
    (retire). As a result, an unprivileged attacker could
    use this flaw to influence speculative execution and/or
    read privileged memory by conducting targeted cache
    side-channel attacks. (CVE-2018-3693)

  - A flaw named SegmentSmack was found in the way the Linux
    kernel handled specially crafted TCP packets. A remote
    attacker could use this flaw to trigger time and
    calculation expensive calls to tcp_collapse_ofo_queue()
    and tcp_prune_ofo_queue() functions by sending specially
    modified packets within ongoing TCP sessions which could
    lead to a CPU saturation and hence a denial of service
    on the system. Maintaining the denial of service
    condition requires continuous two-way TCP sessions to a
    reachable open port, thus the attacks cannot be
    performed using spoofed IP addresses. (CVE-2018-5390)

  - A flaw named FragmentSmack was found in the way the
    Linux kernel handled reassembly of fragmented IPv4 and
    IPv6 packets. A remote attacker could use this flaw to
    trigger time and calculation expensive fragment
    reassembly algorithm by sending specially crafted
    packets which could lead to a CPU saturation and hence a
    denial of service on the system. (CVE-2018-5391)

  - A an integer overflow vulnerability was discovered in
    the Linux kernel, from version 3.4 through 4.15, in the
    drivers/gpu/drm/udl/udl_fb.c:udl_fb_mmap() function. An
    attacker with access to the udldrmfb driver could
    exploit this to obtain full read and write permissions
    on kernel physical pages, resulting in a code execution
    in kernel space. (CVE-2018-8781)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0049");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel-rt packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8781");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');


  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "kernel-rt-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-debug-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-debug-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-debug-devel-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-debug-kvm-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-debug-kvm-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-debuginfo-common-x86_64-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-devel-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-doc-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-kvm-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-kvm-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-trace-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-trace-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-trace-devel-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-trace-kvm-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-trace-kvm-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a"
  ],
  "CGSL MAIN 5.04": [
    "kernel-rt-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-debug-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-debug-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-debug-devel-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-debug-kvm-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-debug-kvm-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-debuginfo-common-x86_64-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-devel-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-doc-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-kvm-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-kvm-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-trace-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-trace-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-trace-devel-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-trace-kvm-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a",
    "kernel-rt-trace-kvm-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.8.205.gaee315a"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-rt");
}
