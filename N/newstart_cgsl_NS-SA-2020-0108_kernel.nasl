##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0108. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143971);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/10");

  script_cve_id(
    "CVE-2015-9289",
    "CVE-2017-17807",
    "CVE-2018-7191",
    "CVE-2018-20169",
    "CVE-2019-3901",
    "CVE-2019-9456",
    "CVE-2019-9503",
    "CVE-2019-11487",
    "CVE-2019-12382",
    "CVE-2019-13233",
    "CVE-2019-14283",
    "CVE-2019-14816",
    "CVE-2019-14895",
    "CVE-2019-14898",
    "CVE-2019-14901",
    "CVE-2019-15916",
    "CVE-2019-17133",
    "CVE-2019-17666",
    "CVE-2019-19338",
    "CVE-2020-10711"
  );
  script_bugtraq_id(
    89937,
    102301,
    108011,
    108054,
    108380,
    108474,
    109055
  );

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : kernel Multiple Vulnerabilities (NS-SA-2020-0108)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has kernel packages installed that are affected by
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

  - In the tun subsystem in the Linux kernel before 4.13.14, dev_get_valid_name is not called before
    register_netdevice. This allows local users to cause a denial of service (NULL pointer dereference and
    panic) via an ioctl(TUNSETIFF) call with a dev name containing a / character. This is similar to
    CVE-2013-4343. (CVE-2018-7191)

  - The Linux kernel before 5.1-rc5 allows page->_refcount reference count overflow, with resultant use-after-
    free issues, if about 140 GiB of RAM exists. This is related to fs/fuse/dev.c, fs/pipe.c, fs/splice.c,
    include/linux/mm.h, include/linux/pipe_fs_i.h, kernel/trace/trace.c, mm/gup.c, and mm/hugetlb.c. It can
    occur with FUSE requests. (CVE-2019-11487)

  - ** DISPUTED ** An issue was discovered in drm_load_edid_firmware in drivers/gpu/drm/drm_edid_load.c in the
    Linux kernel through 5.1.5. There is an unchecked kstrdup of fwstr, which might allow an attacker to cause
    a denial of service (NULL pointer dereference and system crash). NOTE: The vendor disputes this issues as
    not being a vulnerability because kstrdup() returning NULL is handled sufficiently and there is no chance
    for a NULL pointer dereference. (CVE-2019-12382)

  - In arch/x86/lib/insn-eval.c in the Linux kernel before 5.1.9, there is a use-after-free for access to an
    LDT entry because of a race condition between modify_ldt() and a #BR exception for an MPX bounds
    violation. (CVE-2019-13233)

  - In the Linux kernel before 5.2.3, set_geometry in drivers/block/floppy.c does not validate the sect and
    head fields, as demonstrated by an integer overflow and out-of-bounds read. It can be triggered by an
    unprivileged local user when a floppy disk has been inserted. NOTE: QEMU creates the floppy device by
    default. (CVE-2019-14283)

  - There is heap-based buffer overflow in kernel, all versions up to, excluding 5.3, in the marvell wifi chip
    driver in Linux kernel, that allows local users to cause a denial of service(system crash) or possibly
    execute arbitrary code. (CVE-2019-14816)

  - A heap-based buffer overflow was discovered in the Linux kernel, all versions 3.x.x and 4.x.x before
    4.18.0, in Marvell WiFi chip driver. The flaw could occur when the station attempts a connection
    negotiation during the handling of the remote devices country settings. This could allow the remote device
    to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2019-14895)

  - The fix for CVE-2019-11599, affecting the Linux kernel before 5.0.10 was not complete. A local user could
    use this flaw to obtain sensitive information, cause a denial of service, or possibly have other
    unspecified impacts by triggering a race condition with mmget_not_zero or get_task_mm calls.
    (CVE-2019-14898)

  - A heap overflow flaw was found in the Linux kernel, all versions 3.x.x and 4.x.x before 4.18.0, in Marvell
    WiFi chip driver. The vulnerability allows a remote attacker to cause a system crash, resulting in a
    denial of service, or execute arbitrary code. The highest threat with this vulnerability is with the
    availability of the system. If code execution occurs, the code will run with the permissions of root. This
    will affect both confidentiality and integrity of files on the system. (CVE-2019-14901)

  - An issue was discovered in the Linux kernel before 5.0.1. There is a memory leak in
    register_queue_kobjects() in net/core/net-sysfs.c, which will cause denial of service. (CVE-2019-15916)

  - In the Linux kernel through 5.3.2, cfg80211_mgd_wext_giwessid in net/wireless/wext-sme.c does not reject a
    long SSID IE, leading to a Buffer Overflow. (CVE-2019-17133)

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

  - The Broadcom brcmfmac WiFi driver prior to commit a4176ec356c73a46c07c181c6d04039fafa34a9f is vulnerable
    to a frame validation bypass. If the brcmfmac driver receives a firmware event frame from a remote source,
    the is_wlc_event_frame function will cause this frame to be discarded and unprocessed. If the driver
    receives the firmware event frame from the host, the appropriate handler is called. This frame validation
    can be bypassed if the bus used is USB (for instance by a wifi dongle). This can allow firmware event
    frames from a remote source to be processed. In the worst case scenario, by sending specially-crafted WiFi
    packets, a remote, unauthenticated attacker may be able to execute arbitrary code on a vulnerable system.
    More typically, this vulnerability will result in denial-of-service conditions. (CVE-2019-9503)

  - A NULL pointer dereference flaw was found in the Linux kernel's SELinux subsystem in versions before 5.7.
    This flaw occurs while importing the Commercial IP Security Option (CIPSO) protocol's category bitmap into
    the SELinux extensible bitmap via the' ebitmap_netlbl_import' routine. While processing the CIPSO
    restricted bitmap tag in the 'cipso_v4_parsetag_rbm' routine, it sets the security attribute to indicate
    that the category bitmap is present, even if it has not been allocated. This issue leads to a NULL pointer
    dereference issue while importing the same category bitmap into SELinux. This flaw allows a remote network
    user to crash the system kernel, resulting in a denial of service. (CVE-2020-10711)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0108");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14901");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

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
    'bpftool-3.10.0-957.27.2.el7.cgslv5_5.16.208.g08c3da7.lite',
    'kernel-3.10.0-957.27.2.el7.cgslv5_5.16.208.g08c3da7.lite',
    'kernel-abi-whitelists-3.10.0-957.27.2.el7.cgslv5_5.16.208.g08c3da7.lite',
    'kernel-core-3.10.0-957.27.2.el7.cgslv5_5.16.208.g08c3da7.lite',
    'kernel-debug-core-3.10.0-957.27.2.el7.cgslv5_5.16.208.g08c3da7.lite',
    'kernel-debug-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.16.208.g08c3da7.lite',
    'kernel-debug-devel-3.10.0-957.27.2.el7.cgslv5_5.16.208.g08c3da7.lite',
    'kernel-debug-modules-3.10.0-957.27.2.el7.cgslv5_5.16.208.g08c3da7.lite',
    'kernel-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.16.208.g08c3da7.lite',
    'kernel-debuginfo-common-x86_64-3.10.0-957.27.2.el7.cgslv5_5.16.208.g08c3da7.lite',
    'kernel-devel-3.10.0-957.27.2.el7.cgslv5_5.16.208.g08c3da7.lite',
    'kernel-headers-3.10.0-957.27.2.el7.cgslv5_5.16.208.g08c3da7.lite',
    'kernel-modules-3.10.0-957.27.2.el7.cgslv5_5.16.208.g08c3da7.lite',
    'kernel-tools-3.10.0-957.27.2.el7.cgslv5_5.16.208.g08c3da7.lite',
    'kernel-tools-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.16.208.g08c3da7.lite',
    'kernel-tools-libs-3.10.0-957.27.2.el7.cgslv5_5.16.208.g08c3da7.lite',
    'kernel-tools-libs-devel-3.10.0-957.27.2.el7.cgslv5_5.16.208.g08c3da7.lite',
    'perf-3.10.0-957.27.2.el7.cgslv5_5.16.208.g08c3da7.lite',
    'perf-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.16.208.g08c3da7.lite',
    'python-perf-3.10.0-957.27.2.el7.cgslv5_5.16.208.g08c3da7.lite',
    'python-perf-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.16.208.g08c3da7.lite'
  ],
  'CGSL MAIN 5.05': [
    'bpftool-3.10.0-957.27.2.el7.cgslv5_5.16.212.g2ce4410',
    'kernel-3.10.0-957.27.2.el7.cgslv5_5.16.212.g2ce4410',
    'kernel-abi-whitelists-3.10.0-957.27.2.el7.cgslv5_5.16.212.g2ce4410',
    'kernel-debug-3.10.0-957.27.2.el7.cgslv5_5.16.212.g2ce4410',
    'kernel-debug-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.16.212.g2ce4410',
    'kernel-debug-devel-3.10.0-957.27.2.el7.cgslv5_5.16.212.g2ce4410',
    'kernel-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.16.212.g2ce4410',
    'kernel-debuginfo-common-x86_64-3.10.0-957.27.2.el7.cgslv5_5.16.212.g2ce4410',
    'kernel-devel-3.10.0-957.27.2.el7.cgslv5_5.16.212.g2ce4410',
    'kernel-headers-3.10.0-957.27.2.el7.cgslv5_5.16.212.g2ce4410',
    'kernel-tools-3.10.0-957.27.2.el7.cgslv5_5.16.212.g2ce4410',
    'kernel-tools-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.16.212.g2ce4410',
    'kernel-tools-libs-3.10.0-957.27.2.el7.cgslv5_5.16.212.g2ce4410',
    'kernel-tools-libs-devel-3.10.0-957.27.2.el7.cgslv5_5.16.212.g2ce4410',
    'perf-3.10.0-957.27.2.el7.cgslv5_5.16.212.g2ce4410',
    'perf-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.16.212.g2ce4410',
    'python-perf-3.10.0-957.27.2.el7.cgslv5_5.16.212.g2ce4410',
    'python-perf-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.16.212.g2ce4410'
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
