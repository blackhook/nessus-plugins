#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0113. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127351);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id(
    "CVE-2016-6136",
    "CVE-2016-7910",
    "CVE-2016-9576",
    "CVE-2016-10088",
    "CVE-2017-6074",
    "CVE-2017-1000251",
    "CVE-2017-1000253"
  );

  script_name(english:"NewStart CGSL MAIN 4.05 : kernel Multiple Vulnerabilities (NS-SA-2019-0113)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has kernel packages installed that are affected by multiple
vulnerabilities:

  - It was found that the fix for CVE-2016-9576 was
    incomplete: the Linux kernel's sg implementation did not
    properly restrict write operations in situations where
    the KERNEL_DS option is set. A local attacker to read or
    write to arbitrary kernel memory locations or cause a
    denial of service (use-after-free) by leveraging write
    access to a /dev/sg device. (CVE-2016-10088)

  - When creating audit records for parameters to executed
    children processes, an attacker can convince the Linux
    kernel audit subsystem can create corrupt records which
    may allow an attacker to misrepresent or evade logging
    of executing commands. (CVE-2016-6136)

  - A flaw was found in the Linux kernel's implementation of
    seq_file where a local attacker could manipulate memory
    in the put() function pointer. This could lead to memory
    corruption and possible privileged escalation.
    (CVE-2016-7910)

  - It was found that the blk_rq_map_user_iov() function in
    the Linux kernel's block device implementation did not
    properly restrict the type of iterator, which could
    allow a local attacker to read or write to arbitrary
    kernel memory locations or cause a denial of service
    (use-after-free) by leveraging write access to a /dev/sg
    device. (CVE-2016-9576)

  - A stack buffer overflow flaw was found in the way the
    Bluetooth subsystem of the Linux kernel processed
    pending L2CAP configuration responses from a client. On
    systems with the stack protection feature enabled in the
    kernel (CONFIG_CC_STACKPROTECTOR=y, which is enabled on
    all architectures other than s390x and ppc64[le]), an
    unauthenticated attacker able to initiate a connection
    to a system via Bluetooth could use this flaw to crash
    the system. Due to the nature of the stack protection
    feature, code execution cannot be fully ruled out,
    although we believe it is unlikely. On systems without
    the stack protection feature (ppc64[le]; the Bluetooth
    modules are not built on s390x), an unauthenticated
    attacker able to initiate a connection to a system via
    Bluetooth could use this flaw to remotely execute
    arbitrary code on the system with ring 0 (kernel)
    privileges. (CVE-2017-1000251)

  - A flaw was found in the way the Linux kernel loaded ELF
    executables. Provided that an application was built as
    Position Independent Executable (PIE), the loader could
    allow part of that application's data segment to map
    over the memory area reserved for its stack, potentially
    resulting in memory corruption. An unprivileged local
    user with access to SUID (or otherwise privileged) PIE
    binary could use this flaw to escalate their privileges
    on the system. (CVE-2017-1000253)

  - A use-after-free flaw was found in the way the Linux
    kernel's Datagram Congestion Control Protocol (DCCP)
    implementation freed SKB (socket buffer) resources for a
    DCCP_PKT_REQUEST packet when the IPV6_RECVPKTINFO option
    is set on the socket. A local, unprivileged user could
    use this flaw to alter the kernel memory, allowing them
    to escalate their privileges on the system.
    (CVE-2017-6074)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0113");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7910");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-1000251");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

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

if (release !~ "CGSL MAIN 4.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.05": [
    "kernel-2.6.32-642.13.1.el6.cgsl7546",
    "kernel-abi-whitelists-2.6.32-642.13.1.el6.cgsl7442",
    "kernel-debug-2.6.32-642.13.1.el6.cgsl7442",
    "kernel-debug-devel-2.6.32-642.13.1.el6.cgsl7442",
    "kernel-devel-2.6.32-642.13.1.el6.cgsl7546",
    "kernel-doc-2.6.32-642.13.1.el6.cgsl7442",
    "kernel-firmware-2.6.32-642.13.1.el6.cgsl7546",
    "kernel-headers-2.6.32-642.13.1.el6.cgsl7546",
    "perf-2.6.32-642.13.1.el6.cgsl7546"
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
