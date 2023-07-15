##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0074. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160765);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/13");

  script_cve_id(
    "CVE-2020-25211",
    "CVE-2020-29661",
    "CVE-2021-22555",
    "CVE-2021-37576",
    "CVE-2022-0492",
    "CVE-2022-0847"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/16");

  script_name(english:"NewStart CGSL MAIN 6.02 : kernel Multiple Vulnerabilities (NS-SA-2022-0074)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has kernel packages installed that are affected by multiple
vulnerabilities:

  - In the Linux kernel through 5.8.7, local attackers able to inject conntrack netlink configuration could
    overflow a local buffer, causing crashes or triggering use of incorrect protocol numbers in
    ctnetlink_parse_tuple_filter in net/netfilter/nf_conntrack_netlink.c, aka CID-1cc5ef91d2ff.
    (CVE-2020-25211)

  - A locking issue was discovered in the tty subsystem of the Linux kernel through 5.9.13.
    drivers/tty/tty_jobctrl.c allows a use-after-free attack against TIOCSPGRP, aka CID-54ffccbf053b.
    (CVE-2020-29661)

  - A heap out-of-bounds write affecting Linux since v2.6.19-rc1 was discovered in net/netfilter/x_tables.c.
    This allows an attacker to gain privileges or cause a DoS (via heap memory corruption) through user name
    space (CVE-2021-22555)

  - arch/powerpc/kvm/book3s_rtas.c in the Linux kernel through 5.13.5 on the powerpc platform allows KVM guest
    OS users to cause host OS memory corruption via rtas_args.nargs, aka CID-f62f3c20647e. (CVE-2021-37576)

  - A vulnerability was found in the Linux kernel's cgroup_release_agent_write in the
    kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups
    v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.
    (CVE-2022-0492)

  - A flaw was found in the way the flags member of the new pipe buffer structure was lacking proper
    initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus
    contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache
    backed by read only files and as such escalate their privileges on the system. (CVE-2022-0847)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0074");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-25211");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-29661");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-22555");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-37576");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-0492");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-0847");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0847");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Netfilter x_tables Heap OOB Write Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-ipaclones-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-selftests-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-sign-keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'bpftool-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'bpftool-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'kernel-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'kernel-abi-whitelists-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'kernel-core-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'kernel-cross-headers-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'kernel-debug-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'kernel-debug-core-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'kernel-debug-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'kernel-debug-devel-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'kernel-debug-modules-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'kernel-debug-modules-extra-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'kernel-debug-modules-internal-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'kernel-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'kernel-debuginfo-common-x86_64-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'kernel-devel-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'kernel-headers-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'kernel-ipaclones-internal-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'kernel-modules-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'kernel-modules-extra-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'kernel-modules-internal-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'kernel-selftests-internal-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'kernel-sign-keys-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'kernel-tools-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'kernel-tools-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'kernel-tools-libs-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'kernel-tools-libs-devel-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'perf-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'perf-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'python3-perf-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d',
    'python3-perf-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.442.10.gf86d5241d'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel');
}
