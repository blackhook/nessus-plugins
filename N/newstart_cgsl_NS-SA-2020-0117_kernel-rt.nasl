##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0117. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144087);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/14");

  script_cve_id("CVE-2019-3901", "CVE-2019-14898");
  script_bugtraq_id(89937);

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : kernel-rt Multiple Vulnerabilities (NS-SA-2020-0117)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has kernel-rt packages installed that are affected
by multiple vulnerabilities:

  - The fix for CVE-2019-11599, affecting the Linux kernel before 5.0.10 was not complete. A local user could
    use this flaw to obtain sensitive information, cause a denial of service, or possibly have other
    unspecified impacts by triggering a race condition with mmget_not_zero or get_task_mm calls.
    (CVE-2019-14898)

  - A race condition in perf_event_open() allows local attackers to leak sensitive data from setuid programs.
    As no relevant locks (in particular the cred_guard_mutex) are held during the ptrace_may_access() call, it
    is possible for the specified target task to perform an execve() syscall with setuid execution before
    perf_event_alloc() actually attaches to it, allowing an attacker to bypass the ptrace_may_access() check
    and the perf_event_exit_task(current) call that is performed in install_exec_creds() during privileged
    execve() calls. This issue affects kernel versions before 4.8. (CVE-2019-3901)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0117");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel-rt packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14898");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL CORE 5.05': [
    'kernel-rt-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-debug-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-debug-debuginfo-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-debug-devel-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-debug-kvm-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-debug-kvm-debuginfo-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-debuginfo-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-debuginfo-common-x86_64-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-devel-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-doc-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-kvm-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-kvm-debuginfo-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-trace-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-trace-debuginfo-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-trace-devel-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-trace-kvm-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-trace-kvm-debuginfo-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a'
  ],
  'CGSL MAIN 5.05': [
    'kernel-rt-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-debug-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-debug-debuginfo-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-debug-devel-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-debug-kvm-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-debug-kvm-debuginfo-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-debuginfo-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-debuginfo-common-x86_64-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-devel-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-doc-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-kvm-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-kvm-debuginfo-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-trace-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-trace-debuginfo-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-trace-devel-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-trace-kvm-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a',
    'kernel-rt-trace-kvm-debuginfo-3.10.0-957.27.2.rt56.940.el7.cgslv5_5.12.102.gd28955a'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-rt');
}
