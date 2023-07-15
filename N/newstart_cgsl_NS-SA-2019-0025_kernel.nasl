#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0025. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127185);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2017-11600",
    "CVE-2017-13215",
    "CVE-2017-16939",
    "CVE-2018-1068",
    "CVE-2018-3665",
    "CVE-2018-8897",
    "CVE-2018-10675",
    "CVE-2018-1000199"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : kernel Multiple Vulnerabilities (NS-SA-2019-0025)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has kernel packages installed that are affected by
multiple vulnerabilities:

  - The xfrm_migrate() function in the
    net/xfrm/xfrm_policy.c file in the Linux kernel built
    with CONFIG_XFRM_MIGRATE does not verify if the dir
    parameter is less than XFRM_POLICY_MAX. This allows a
    local attacker to cause a denial of service (out-of-
    bounds access) or possibly have unspecified other impact
    by sending a XFRM_MSG_MIGRATE netlink message. This flaw
    is present in the Linux kernel since an introduction of
    XFRM_MSG_MIGRATE in 2.6.21-rc1, up to 4.13-rc3.
    (CVE-2017-11600)

  - A flaw was found in the Linux kernel's skcipher
    component, which affects the skcipher_recvmsg function.
    Attackers using a specific input can lead to a privilege
    escalation. (CVE-2017-13215)

  - The Linux kernel is vulerable to a use-after-free flaw
    when Transformation User configuration
    interface(CONFIG_XFRM_USER) compile-time configuration
    were enabled. This vulnerability occurs while closing a
    xfrm netlink socket in xfrm_dump_policy_done. A
    user/process could abuse this flaw to potentially
    escalate their privileges on a system. (CVE-2017-16939)

  - An address corruption flaw was discovered in the Linux
    kernel built with hardware breakpoint
    (CONFIG_HAVE_HW_BREAKPOINT) support. While modifying a
    h/w breakpoint via 'modify_user_hw_breakpoint' routine,
    an unprivileged user/process could use this flaw to
    crash the system kernel resulting in DoS OR to
    potentially escalate privileges on a the system.
    (CVE-2018-1000199)

  - The do_get_mempolicy() function in mm/mempolicy.c in the
    Linux kernel allows local users to hit a use-after-free
    bug via crafted system calls and thus cause a denial of
    service (DoS) or possibly have unspecified other impact.
    Due to the nature of the flaw, privilege escalation
    cannot be fully ruled out. (CVE-2018-10675)

  - A flaw was found in the Linux kernel's implementation of
    32-bit syscall interface for bridging. This allowed a
    privileged user to arbitrarily write to a limited range
    of kernel memory. (CVE-2018-1068)

  - A Floating Point Unit (FPU) state information leakage
    flaw was found in the way the Linux kernel saved and
    restored the FPU state during task switch. Linux kernels
    that follow the Lazy FPU Restore scheme are vulnerable
    to the FPU state information leakage issue. An
    unprivileged local attacker could use this flaw to read
    FPU state bits by conducting targeted cache side-channel
    attacks, similar to the Meltdown vulnerability disclosed
    earlier this year. (CVE-2018-3665)

  - A flaw was found in the way the Linux kernel handled
    exceptions delivered after a stack switch operation via
    Mov SS or Pop SS instructions. During the stack switch
    operation, the processor did not deliver interrupts and
    exceptions, rather they are delivered once the first
    instruction after the stack switch is executed. An
    unprivileged system user could use this flaw to crash
    the system kernel resulting in the denial of service.
    (CVE-2018-8897)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0025");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8897");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows POP/MOV SS Local Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");


  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/24");
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
    "kernel-3.10.0-693.21.1.el7.cgslv5u4lite.0.116.gcc6e0f4",
    "kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5u4lite.0.116.gcc6e0f4",
    "kernel-core-3.10.0-693.21.1.el7.cgslv5u4lite.0.116.gcc6e0f4",
    "kernel-debug-core-3.10.0-693.21.1.el7.cgslv5u4lite.0.116.gcc6e0f4",
    "kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5u4lite.0.116.gcc6e0f4",
    "kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5u4lite.0.116.gcc6e0f4",
    "kernel-debug-modules-3.10.0-693.21.1.el7.cgslv5u4lite.0.116.gcc6e0f4",
    "kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5u4lite.0.116.gcc6e0f4",
    "kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5u4lite.0.116.gcc6e0f4",
    "kernel-devel-3.10.0-693.21.1.el7.cgslv5u4lite.0.116.gcc6e0f4",
    "kernel-doc-3.10.0-693.21.1.el7.cgslv5u4lite.0.116.gcc6e0f4",
    "kernel-headers-3.10.0-693.21.1.el7.cgslv5u4lite.0.116.gcc6e0f4",
    "kernel-modules-3.10.0-693.21.1.el7.cgslv5u4lite.0.116.gcc6e0f4",
    "kernel-tools-3.10.0-693.21.1.el7.cgslv5u4lite.0.116.gcc6e0f4",
    "kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5u4lite.0.116.gcc6e0f4",
    "kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5u4lite.0.116.gcc6e0f4",
    "kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5u4lite.0.116.gcc6e0f4",
    "perf-3.10.0-693.21.1.el7.cgslv5u4lite.0.116.gcc6e0f4",
    "perf-debuginfo-3.10.0-693.21.1.el7.cgslv5u4lite.0.116.gcc6e0f4",
    "python-perf-3.10.0-693.21.1.el7.cgslv5u4lite.0.116.gcc6e0f4",
    "python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5u4lite.0.116.gcc6e0f4"
  ],
  "CGSL MAIN 5.04": [
    "kernel-3.10.0-693.21.1.el7.cgslv5u4.0.113.gdca0b39",
    "kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5u4.0.113.gdca0b39",
    "kernel-debug-3.10.0-693.21.1.el7.cgslv5u4.0.113.gdca0b39",
    "kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5u4.0.113.gdca0b39",
    "kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5u4.0.113.gdca0b39",
    "kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5u4.0.113.gdca0b39",
    "kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5u4.0.113.gdca0b39",
    "kernel-devel-3.10.0-693.21.1.el7.cgslv5u4.0.113.gdca0b39",
    "kernel-doc-3.10.0-693.21.1.el7.cgslv5u4.0.113.gdca0b39",
    "kernel-headers-3.10.0-693.21.1.el7.cgslv5u4.0.113.gdca0b39",
    "kernel-tools-3.10.0-693.21.1.el7.cgslv5u4.0.113.gdca0b39",
    "kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5u4.0.113.gdca0b39",
    "kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5u4.0.113.gdca0b39",
    "kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5u4.0.113.gdca0b39",
    "perf-3.10.0-693.21.1.el7.cgslv5u4.0.113.gdca0b39",
    "perf-debuginfo-3.10.0-693.21.1.el7.cgslv5u4.0.113.gdca0b39",
    "python-perf-3.10.0-693.21.1.el7.cgslv5u4.0.113.gdca0b39",
    "python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5u4.0.113.gdca0b39"
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
