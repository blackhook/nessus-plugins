#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0041. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(141400);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2015-9289",
    "CVE-2017-17807",
    "CVE-2018-20169",
    "CVE-2019-3901",
    "CVE-2019-9456",
    "CVE-2019-14283",
    "CVE-2019-17666",
    "CVE-2019-19338"
  );
  script_bugtraq_id(89937, 102301);

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : kernel Multiple Vulnerabilities (NS-SA-2020-0041)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has kernel packages installed that are affected by
multiple vulnerabilities:

  - In the Linux kernel before 4.1.4, a buffer overflow occurs when checking userspace params in
    drivers/media/dvb-frontends/cx24116.c. The maximum size for a DiSEqC command is 6, according to the
    userspace API. However, the code allows larger values such as 23. (CVE-2015-9289)

  - The KEYS subsystem in the Linux kernel before 4.14.6 omitted an access-control check when adding a key to
    the current task's default request-key keyring via the request_key() system call, allowing a local user
    to use a sequence of crafted system calls to add keys to a keyring with only Search permission (not Write
    permission) to that keyring, related to construct_get_dest_keyring() in security/keys/request_key.c.
    (CVE-2017-17807)

  - An issue was discovered in the Linux kernel before 4.19.9. The USB subsystem mishandles size checks during
    the reading of an extra descriptor, related to __usb_get_extra_descriptor in drivers/usb/core/usb.c.
    (CVE-2018-20169)

  - In the Linux kernel before 5.2.3, set_geometry in drivers/block/floppy.c does not validate the sect and
    head fields, as demonstrated by an integer overflow and out-of-bounds read. It can be triggered by an
    unprivileged local user when a floppy disk has been inserted. NOTE: QEMU creates the floppy device by
    default. (CVE-2019-14283)

  - rtl_p2p_noa_ie in drivers/net/wireless/realtek/rtlwifi/ps.c in the Linux kernel through 5.3.6 lacks a
    certain upper-bound check, leading to a buffer overflow. (CVE-2019-17666)

  - A flaw was found in the fix for CVE-2019-11135, in the Linux upstream kernel versions before 5.5 where,
    the way Intel CPUs handle speculative execution of instructions when a TSX Asynchronous Abort (TAA) error
    occurs. When a guest is running on a host CPU affected by the TAA flaw (TAA_NO=0), but is not affected by
    the MDS issue (MDS_NO=1), the guest was to clear the affected buffers by using a VERW instruction
    mechanism. But when the MDS_NO=1 bit was exported to the guests, the guests did not use the VERW mechanism
    to clear the affected buffers. This issue affects guests running on Cascade Lake CPUs and requires that
    host has 'TSX' enabled. Confidentiality of data is the highest threat associated with this vulnerability.
    (CVE-2019-19338)

  - A race condition in perf_event_open() allows local attackers to leak sensitive data from setuid programs.
    As no relevant locks (in particular the cred_guard_mutex) are held during the ptrace_may_access() call, it
    is possible for the specified target task to perform an execve() syscall with setuid execution before
    perf_event_alloc() actually attaches to it, allowing an attacker to bypass the ptrace_may_access() check
    and the perf_event_exit_task(current) call that is performed in install_exec_creds() during privileged
    execve() calls. This issue affects kernel versions before 4.8. (CVE-2019-3901)

  - In the Android kernel in Pixel C USB monitor driver there is a possible OOB write due to a missing bounds
    check. This could lead to local escalation of privilege with System execution privileges needed. User
    interaction is not needed for exploitation. (CVE-2019-9456)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0041");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17666");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL CORE 5.04': [
    'kernel-3.10.0-693.21.1.el7.cgslv5_4.43.616.gf297bb0.lite',
    'kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.43.616.gf297bb0.lite',
    'kernel-core-3.10.0-693.21.1.el7.cgslv5_4.43.616.gf297bb0.lite',
    'kernel-debug-core-3.10.0-693.21.1.el7.cgslv5_4.43.616.gf297bb0.lite',
    'kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.43.616.gf297bb0.lite',
    'kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.43.616.gf297bb0.lite',
    'kernel-debug-modules-3.10.0-693.21.1.el7.cgslv5_4.43.616.gf297bb0.lite',
    'kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.43.616.gf297bb0.lite',
    'kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.43.616.gf297bb0.lite',
    'kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.43.616.gf297bb0.lite',
    'kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.43.616.gf297bb0.lite',
    'kernel-modules-3.10.0-693.21.1.el7.cgslv5_4.43.616.gf297bb0.lite',
    'kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.43.616.gf297bb0.lite',
    'kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.43.616.gf297bb0.lite',
    'kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.43.616.gf297bb0.lite',
    'kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.43.616.gf297bb0.lite',
    'kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.43.616.gf297bb0.lite',
    'perf-3.10.0-693.21.1.el7.cgslv5_4.43.616.gf297bb0.lite',
    'perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.43.616.gf297bb0.lite',
    'python-perf-3.10.0-693.21.1.el7.cgslv5_4.43.616.gf297bb0.lite',
    'python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.43.616.gf297bb0.lite'
  ],
  'CGSL MAIN 5.04': [
    'kernel-3.10.0-693.21.1.el7.cgslv5_4.41.613.g62a9c8e',
    'kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.41.613.g62a9c8e',
    'kernel-debug-3.10.0-693.21.1.el7.cgslv5_4.41.613.g62a9c8e',
    'kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.41.613.g62a9c8e',
    'kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.41.613.g62a9c8e',
    'kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.41.613.g62a9c8e',
    'kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.41.613.g62a9c8e',
    'kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.41.613.g62a9c8e',
    'kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.41.613.g62a9c8e',
    'kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.41.613.g62a9c8e',
    'kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.41.613.g62a9c8e',
    'kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.41.613.g62a9c8e',
    'kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.41.613.g62a9c8e',
    'kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.41.613.g62a9c8e',
    'perf-3.10.0-693.21.1.el7.cgslv5_4.41.613.g62a9c8e',
    'perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.41.613.g62a9c8e',
    'python-perf-3.10.0-693.21.1.el7.cgslv5_4.41.613.g62a9c8e',
    'python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.41.613.g62a9c8e'
  ]
};
pkg_list = pkgs[release];

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel');
}
