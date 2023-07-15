#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2016-2574.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(94697);
  script_version("2.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/08");

  script_cve_id(
    "CVE-2013-4312",
    "CVE-2015-8374",
    "CVE-2015-8543",
    "CVE-2015-8746",
    "CVE-2015-8812",
    "CVE-2015-8844",
    "CVE-2015-8845",
    "CVE-2015-8956",
    "CVE-2016-2053",
    "CVE-2016-2069",
    "CVE-2016-2117",
    "CVE-2016-2384",
    "CVE-2016-2847",
    "CVE-2016-3044",
    "CVE-2016-3070",
    "CVE-2016-3156",
    "CVE-2016-3699",
    "CVE-2016-3841",
    "CVE-2016-4569",
    "CVE-2016-4578",
    "CVE-2016-4581",
    "CVE-2016-4794",
    "CVE-2016-5412",
    "CVE-2016-5828",
    "CVE-2016-5829",
    "CVE-2016-6136",
    "CVE-2016-6198",
    "CVE-2016-6327",
    "CVE-2016-6480",
    "CVE-2016-7914",
    "CVE-2016-7915",
    "CVE-2016-9794",
    "CVE-2017-13167",
    "CVE-2018-16597"
  );
  script_xref(name:"RHSA", value:"2016:2574");

  script_name(english:"Oracle Linux 7 : kernel (ELSA-2016-2574)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2016-2574 advisory.

  - The Linux kernel before 4.4.1 allows local users to bypass file-descriptor limits and cause a denial of
    service (memory consumption) by sending each descriptor over a UNIX socket before closing it, related to
    net/unix/af_unix.c and net/unix/garbage.c. (CVE-2013-4312)

  - The networking implementation in the Linux kernel through 4.3.3, as used in Android and other products,
    does not validate protocol identifiers for certain protocol families, which allows local users to cause a
    denial of service (NULL function pointer dereference and system crash) or possibly gain privileges by
    leveraging CLONE_NEWUSER support to execute a crafted SOCK_RAW application. (CVE-2015-8543)

  - The atl2_probe function in drivers/net/ethernet/atheros/atlx/atl2.c in the Linux kernel through 4.5.2
    incorrectly enables scatter/gather I/O, which allows remote attackers to obtain sensitive information from
    kernel memory by reading packet data. (CVE-2016-2117)

  - The filesystem layer in the Linux kernel before 4.5.5 proceeds with post-rename operations after an
    OverlayFS file is renamed to a self-hardlink, which allows local users to cause a denial of service
    (system crash) via a rename system call, related to fs/namei.c and fs/open.c. (CVE-2016-6198)

  - Race condition in arch/x86/mm/tlb.c in the Linux kernel before 4.4.1 allows local users to gain privileges
    by triggering access to a paging structure by a different CPU. (CVE-2016-2069)

  - The IPv4 implementation in the Linux kernel before 4.5.2 mishandles destruction of device objects, which
    allows guest OS users to cause a denial of service (host OS networking outage) by arranging for a large
    number of IP addresses. (CVE-2016-3156)

  - fs/pnode.c in the Linux kernel before 4.5.4 does not properly traverse a mount propagation tree in a
    certain case involving a slave mount, which allows local users to cause a denial of service (NULL pointer
    dereference and OOPS) via a crafted series of mount system calls. (CVE-2016-4581)

  - fs/pipe.c in the Linux kernel before 4.5 does not limit the amount of unread data in pipes, which allows
    local users to cause a denial of service (memory consumption) by creating many pipes with non-default
    sizes. (CVE-2016-2847)

  - fs/btrfs/inode.c in the Linux kernel before 4.3.3 mishandles compressed inline extents, which allows local
    users to obtain sensitive pre-truncation information from a file via a clone action. (CVE-2015-8374)

  - Multiple heap-based buffer overflows in the hiddev_ioctl_usage function in drivers/hid/usbhid/hiddev.c in
    the Linux kernel through 4.6.3 allow local users to cause a denial of service or possibly have unspecified
    other impact via a crafted (1) HIDIOCGUSAGES or (2) HIDIOCSUSAGES ioctl call. (CVE-2016-5829)

  - The signal implementation in the Linux kernel before 4.3.5 on powerpc platforms does not check for an MSR
    with both the S and T bits set, which allows local users to cause a denial of service (TM Bad Thing
    exception and panic) via a crafted application. (CVE-2015-8844)

  - The tm_reclaim_thread function in arch/powerpc/kernel/process.c in the Linux kernel before 4.4.1 on
    powerpc platforms does not ensure that TM suspend mode exists before proceeding with a tm_reclaim call,
    which allows local users to cause a denial of service (TM Bad Thing exception and panic) via a crafted
    application. (CVE-2015-8845)

  - The rfcomm_sock_bind function in net/bluetooth/rfcomm/sock.c in the Linux kernel before 4.2 allows local
    users to obtain sensitive information or cause a denial of service (NULL pointer dereference) via vectors
    involving a bind system call on a Bluetooth RFCOMM socket. (CVE-2015-8956)

  - The asn1_ber_decoder function in lib/asn1_decoder.c in the Linux kernel before 4.3 allows attackers to
    cause a denial of service (panic) via an ASN.1 BER file that lacks a public key, leading to mishandling by
    the public_key_verify_signature function in crypto/asymmetric_keys/public_key.c. (CVE-2016-2053)

  - Double free vulnerability in the snd_usbmidi_create function in sound/usb/midi.c in the Linux kernel
    before 4.5 allows physically proximate attackers to cause a denial of service (panic) or possibly have
    unspecified other impact via vectors involving an invalid USB descriptor. (CVE-2016-2384)

  - The snd_timer_user_params function in sound/core/timer.c in the Linux kernel through 4.6 does not
    initialize a certain data structure, which allows local users to obtain sensitive information from kernel
    stack memory via crafted use of the ALSA timer interface. (CVE-2016-4569)

  - sound/core/timer.c in the Linux kernel through 4.6 does not initialize certain r1 data structures, which
    allows local users to obtain sensitive information from kernel stack memory via crafted use of the ALSA
    timer interface, related to the (1) snd_timer_user_ccallback and (2) snd_timer_user_tinterrupt functions.
    (CVE-2016-4578)

  - arch/powerpc/kvm/book3s_hv_rmhandlers.S in the Linux kernel through 4.7 on PowerPC platforms, when
    CONFIG_KVM_BOOK3S_64_HV is enabled, allows guest OS users to cause a denial of service (host OS infinite
    loop) by making a H_CEDE hypercall during the existence of a suspended transaction. (CVE-2016-5412)

  - drivers/infiniband/ulp/srpt/ib_srpt.c in the Linux kernel before 4.5.1 allows local users to cause a
    denial of service (NULL pointer dereference and system crash) by using an ABORT_TASK command to abort a
    device write operation. (CVE-2016-6327)

  - Race condition in the ioctl_send_fib function in drivers/scsi/aacraid/commctrl.c in the Linux kernel
    through 4.7 allows local users to cause a denial of service (out-of-bounds access or system crash) by
    changing a certain size value, aka a double fetch vulnerability. (CVE-2016-6480)

  - fs/nfs/nfs4proc.c in the NFS client in the Linux kernel before 4.2.2 does not properly initialize memory
    for migration recovery operations, which allows remote NFS servers to cause a denial of service (NULL
    pointer dereference and panic) via crafted network traffic. (CVE-2015-8746)

  - drivers/infiniband/hw/cxgb3/iwch_cm.c in the Linux kernel before 4.5 does not properly identify error
    conditions, which allows remote attackers to execute arbitrary code or cause a denial of service (use-
    after-free) via crafted packets. (CVE-2015-8812)

  - The trace_writeback_dirty_page implementation in include/trace/events/writeback.h in the Linux kernel
    before 4.4 improperly interacts with mm/migrate.c, which allows local users to cause a denial of service
    (NULL pointer dereference and system crash) or possibly have unspecified other impact by triggering a
    certain page move. (CVE-2016-3070)

  - The Linux kernel, as used in Red Hat Enterprise Linux 7.2 and Red Hat Enterprise MRG 2 and when booted
    with UEFI Secure Boot enabled, allows local users to bypass intended Secure Boot restrictions and execute
    untrusted code by appending ACPI tables to the initrd. (CVE-2016-3699)

  - The IPv6 stack in the Linux kernel before 4.3.3 mishandles options data, which allows local users to gain
    privileges or cause a denial of service (use-after-free and system crash) via a crafted sendmsg system
    call. (CVE-2016-3841)

  - Use-after-free vulnerability in mm/percpu.c in the Linux kernel through 4.6 allows local users to cause a
    denial of service (BUG) or possibly have unspecified other impact via crafted use of the mmap and bpf
    system calls. (CVE-2016-4794)

  - The start_thread function in arch/powerpc/kernel/process.c in the Linux kernel through 4.6.3 on powerpc
    platforms mishandles transactional state, which allows local users to cause a denial of service (invalid
    process state or TM Bad Thing exception, and system crash) or possibly have unspecified other impact by
    starting and suspending a transaction before an exec system call. (CVE-2016-5828)

  - Race condition in the audit_log_single_execve_arg function in kernel/auditsc.c in the Linux kernel through
    4.7 allows local users to bypass intended character-set restrictions or disrupt system-call auditing by
    changing a certain string, aka a double fetch vulnerability. (CVE-2016-6136)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2016-2574.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8812");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['3.10.0-514.el7'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2016-2574');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '3.10';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-3.10.0-514.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-3.10.0'},
    {'reference':'kernel-abi-whitelists-3.10.0-514.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-3.10.0'},
    {'reference':'kernel-debug-3.10.0-514.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-3.10.0'},
    {'reference':'kernel-debug-devel-3.10.0-514.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-3.10.0'},
    {'reference':'kernel-devel-3.10.0-514.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-3.10.0'},
    {'reference':'kernel-headers-3.10.0-514.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-3.10.0'},
    {'reference':'kernel-tools-3.10.0-514.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-3.10.0'},
    {'reference':'kernel-tools-libs-3.10.0-514.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-3.10.0'},
    {'reference':'kernel-tools-libs-devel-3.10.0-514.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-3.10.0'},
    {'reference':'perf-3.10.0-514.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-3.10.0-514.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release) {
    if (exists_check) {
        if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel / kernel-abi-whitelists / kernel-debug / etc');
}
