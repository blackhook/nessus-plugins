#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0177. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128689);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2017-17805",
    "CVE-2018-17972",
    "CVE-2019-1125",
    "CVE-2019-3896",
    "CVE-2019-5489",
    "CVE-2019-11477",
    "CVE-2019-11478",
    "CVE-2019-11479"
  );
  script_xref(name:"CEA-ID", value:"CEA-2019-0456");

  script_name(english:"NewStart CGSL MAIN 4.06 : kernel Multiple Vulnerabilities (NS-SA-2019-0177)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.06, has kernel packages installed that are affected by multiple
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

  - The mincore() implementation in mm/mincore.c in the
    Linux kernel through 4.19.13 allowed local attackers to
    observe page cache access patterns of other processes on
    the same system, potentially allowing sniffing of secret
    information. (Fixing this affects the output of the
    fincore program.) Limited remote exploitation may be
    possible, as demonstrated by latency differences in
    accessing public files from an Apache HTTP Server.
    (CVE-2019-5489)

  - An issue was discovered in the proc_pid_stack function
    in fs/proc/base.c in the Linux kernel through 4.18.11.
    It does not ensure that only root may inspect the kernel
    stack of an arbitrary task, allowing a local attacker to
    exploit racy stack unwinding and leak kernel task stack
    contents. (CVE-2018-17972)

  - Jonathan Looney discovered that the
    TCP_SKB_CB(skb)->tcp_gso_segs value was subject to an
    integer overflow in the Linux kernel when handling TCP
    Selective Acknowledgments (SACKs). A remote attacker
    could use this to cause a denial of service. This has
    been fixed in stable kernel releases 4.4.182, 4.9.182,
    4.14.127, 4.19.52, 5.1.11, and is fixed in commit
    3b4929f65b0d8249f19a50245cd88ed1a2f78cff.
    (CVE-2019-11477)

  - A double-free can happen in idr_remove_all() in
    lib/idr.c in the Linux kernel 2.6 branch. An
    unprivileged local attacker can use this flaw for a
    privilege escalation or for a system crash and a denial
    of service (DoS). (CVE-2019-3896)

  - An information disclosure vulnerability exists when
    certain central processing units (CPU) speculatively
    access memory, aka 'Windows Kernel Information
    Disclosure Vulnerability'. This CVE ID is unique from
    CVE-2019-1071, CVE-2019-1073. (CVE-2019-1125)

  - Jonathan Looney discovered that the TCP retransmission
    queue implementation in tcp_fragment in the Linux kernel
    could be fragmented when handling certain TCP Selective
    Acknowledgment (SACK) sequences. A remote attacker could
    use this to cause a denial of service. This has been
    fixed in stable kernel releases 4.4.182, 4.9.182,
    4.14.127, 4.19.52, 5.1.11, and is fixed in commit
    f070ef2ac66716357066b683fb0baf55f8191a2e.
    (CVE-2019-11478)

  - Jonathan Looney discovered that the Linux kernel default
    MSS is hard-coded to 48 bytes. This allows a remote peer
    to fragment TCP resend queues significantly more than if
    a larger MSS were enforced. A remote attacker could use
    this to cause a denial of service. This has been fixed
    in stable kernel releases 4.4.182, 4.9.182, 4.14.127,
    4.19.52, 5.1.11, and is fixed in commits
    967c05aee439e6e5d7d805e195b3a20ef5c433d6 and
    5f3e2bf008c2221478101ee72f5cb4654b9fc363.
    (CVE-2019-11479)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0177");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3896");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (release !~ "CGSL MAIN 4.06")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.06');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.06": [
    "kernel-2.6.32-754.18.2.el6.cgslv4_6.0.28.gda17c11",
    "kernel-abi-whitelists-2.6.32-754.18.2.el6.cgslv4_6.0.28.gda17c11",
    "kernel-debug-2.6.32-754.18.2.el6.cgslv4_6.0.28.gda17c11",
    "kernel-debug-debuginfo-2.6.32-754.18.2.el6.cgslv4_6.0.28.gda17c11",
    "kernel-debug-devel-2.6.32-754.18.2.el6.cgslv4_6.0.28.gda17c11",
    "kernel-debuginfo-2.6.32-754.18.2.el6.cgslv4_6.0.28.gda17c11",
    "kernel-debuginfo-common-x86_64-2.6.32-754.18.2.el6.cgslv4_6.0.28.gda17c11",
    "kernel-devel-2.6.32-754.18.2.el6.cgslv4_6.0.28.gda17c11",
    "kernel-doc-2.6.32-754.18.2.el6.cgslv4_6.0.28.gda17c11",
    "kernel-firmware-2.6.32-754.18.2.el6.cgslv4_6.0.28.gda17c11",
    "kernel-headers-2.6.32-754.18.2.el6.cgslv4_6.0.28.gda17c11",
    "perf-2.6.32-754.18.2.el6.cgslv4_6.0.28.gda17c11",
    "perf-debuginfo-2.6.32-754.18.2.el6.cgslv4_6.0.28.gda17c11",
    "python-perf-2.6.32-754.18.2.el6.cgslv4_6.0.28.gda17c11",
    "python-perf-debuginfo-2.6.32-754.18.2.el6.cgslv4_6.0.28.gda17c11"
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
