#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0143. The text
# itself is copyright (C) ZTE, Inc.


include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127408);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2016-9555",
    "CVE-2017-5753",
    "CVE-2017-5754",
    "CVE-2017-7308",
    "CVE-2017-8824",
    "CVE-2017-13166",
    "CVE-2017-1000112",
    "CVE-2018-3639",
    "CVE-2018-3693",
    "CVE-2018-5390",
    "CVE-2018-5391",
    "CVE-2018-10675",
    "CVE-2018-10901",
    "CVE-2018-14634"
  );
  script_bugtraq_id(
    102371,
    102378,
    104976,
    105407,
    106128
  );

  script_name(english:"NewStart CGSL MAIN 4.05 : kernel Multiple Vulnerabilities (NS-SA-2019-0143)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has kernel packages installed that are affected by multiple
vulnerabilities:

  - A flaw was found in the Linux kernel's implementation of
    the SCTP protocol. A remote attacker could trigger an
    out-of-bounds read with an offset of up to 64kB
    potentially causing the system to crash. (CVE-2016-9555)

  - An exploitable memory corruption flaw was found in the
    Linux kernel. The append path can be erroneously
    switched from UFO to non-UFO in ip_ufo_append_data()
    when building an UFO packet with MSG_MORE option. If
    unprivileged user namespaces are available, this flaw
    can be exploited to gain root privileges.
    (CVE-2017-1000112)

  - A bug in the 32-bit compatibility layer of the ioctl
    handling code of the v4l2 video driver in the Linux
    kernel has been found. A memory protection mechanism
    ensuring that user-provided buffers always point to a
    userspace memory were disabled, allowing destination
    address to be in a kernel space. This flaw could be
    exploited by an attacker to overwrite a kernel memory
    from an unprivileged userspace process, leading to
    privilege escalation. (CVE-2017-13166)

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

  - It was found that the packet_set_ring() function of the
    Linux kernel's networking implementation did not
    properly validate certain block-size data. A local
    attacker with CAP_NET_RAW capability could use this flaw
    to trigger a buffer overflow resulting in a system crash
    or a privilege escalation. (CVE-2017-7308)

  - A use-after-free vulnerability was found in DCCP socket
    code affecting the Linux kernel since 2.6.16. This
    vulnerability could allow an attacker to their escalate
    privileges. (CVE-2017-8824)

  - The do_get_mempolicy() function in mm/mempolicy.c in the
    Linux kernel allows local users to hit a use-after-free
    bug via crafted system calls and thus cause a denial of
    service (DoS) or possibly have unspecified other impact.
    Due to the nature of the flaw, privilege escalation
    cannot be fully ruled out. (CVE-2018-10675)

  - A flaw was found in Linux kernel's KVM virtualization
    subsystem. The VMX code does not restore the GDT.LIMIT
    to the previous host value, but instead sets it to 64KB.
    With a corrupted GDT limit a host's userspace code has
    an ability to place malicious entries in the GDT,
    particularly to the per-cpu variables. An attacker can
    use this to escalate their privileges. (CVE-2018-10901)

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

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0143");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9555");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'AF_PACKET packet_set_ring Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
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

if (release !~ "CGSL MAIN 4.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.05": [
    "kernel-2.6.32-642.13.1.el6.cgsl7763",
    "kernel-abi-whitelists-2.6.32-642.13.1.el6.cgsl7763",
    "kernel-debug-2.6.32-642.13.1.el6.cgsl7763",
    "kernel-debug-debuginfo-2.6.32-642.13.1.el6.cgsl7763",
    "kernel-debug-devel-2.6.32-642.13.1.el6.cgsl7763",
    "kernel-debuginfo-2.6.32-642.13.1.el6.cgsl7763",
    "kernel-debuginfo-common-x86_64-2.6.32-642.13.1.el6.cgsl7763",
    "kernel-devel-2.6.32-642.13.1.el6.cgsl7763",
    "kernel-doc-2.6.32-642.13.1.el6.cgsl7763",
    "kernel-firmware-2.6.32-642.13.1.el6.cgsl7763",
    "kernel-headers-2.6.32-642.13.1.el6.cgsl7763",
    "perf-2.6.32-642.13.1.el6.cgsl7763",
    "perf-debuginfo-2.6.32-642.13.1.el6.cgsl7763",
    "python-perf-2.6.32-642.13.1.el6.cgsl7763",
    "python-perf-debuginfo-2.6.32-642.13.1.el6.cgsl7763"
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
