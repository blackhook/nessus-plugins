#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2018-4134.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110583);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/08");

  script_cve_id(
    "CVE-2016-2384",
    "CVE-2016-2543",
    "CVE-2016-2544",
    "CVE-2016-2545",
    "CVE-2016-2547",
    "CVE-2016-2548",
    "CVE-2016-2549",
    "CVE-2017-17741",
    "CVE-2017-1000410",
    "CVE-2018-3665",
    "CVE-2018-10323",
    "CVE-2018-1000199"
  );
  script_xref(name:"IAVA", value:"2018-A-0196-S");

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2018-4134)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2018-4134 advisory.

  - Double free vulnerability in the snd_usbmidi_create function in sound/usb/midi.c in the Linux kernel
    before 4.5 allows physically proximate attackers to cause a denial of service (panic) or possibly have
    unspecified other impact via vectors involving an invalid USB descriptor. (CVE-2016-2384)

  - The Linux kernel version 3.3-rc1 and later is affected by a vulnerability lies in the processing of
    incoming L2CAP commands - ConfigRequest, and ConfigResponse messages. This info leak is a result of
    uninitialized stack variables that may be returned to an attacker in their uninitialized state. By
    manipulating the code flows that precede the handling of these configuration messages, an attacker can
    also gain some control over which data will be held in the uninitialized stack variables. This can allow
    him to bypass KASLR, and stack canaries protection - as both pointers and stack canaries may be leaked in
    this manner. Combining this vulnerability (for example) with the previously disclosed RCE vulnerability in
    L2CAP configuration parsing (CVE-2017-1000251) may allow an attacker to exploit the RCE against kernels
    which were built with the above mitigations. These are the specifics of this vulnerability: In the
    function l2cap_parse_conf_rsp and in the function l2cap_parse_conf_req the following variable is declared
    without initialization: struct l2cap_conf_efs efs; In addition, when parsing input configuration
    parameters in both of these functions, the switch case for handling EFS elements may skip the memcpy call
    that will write to the efs variable: ... case L2CAP_CONF_EFS: if (olen == sizeof(efs)) memcpy(&efs;, (void
    *)val, olen); ... The olen in the above if is attacker controlled, and regardless of that if, in both of
    these functions the efs variable would eventually be added to the outgoing configuration request that is
    being built: l2cap_add_conf_opt(&ptr;, L2CAP_CONF_EFS, sizeof(efs), (unsigned long) &efs;); So by sending a
    configuration request, or response, that contains an L2CAP_CONF_EFS element, but with an element length
    that is not sizeof(efs) - the memcpy to the uninitialized efs variable can be avoided, and the
    uninitialized variable would be returned to the attacker (16 bytes). (CVE-2017-1000410)

  - The Linux Kernel version 3.18 contains a dangerous feature vulnerability in modify_user_hw_breakpoint()
    that can result in crash and possibly memory corruption. This attack appear to be exploitable via local
    code execution and the ability to use ptrace. This vulnerability appears to have been fixed in git commit
    f67b15037a7a50c57f72e69a6d59941ad90a0f0f. (CVE-2018-1000199)

  - The KVM implementation in the Linux kernel through 4.14.7 allows attackers to obtain potentially sensitive
    information from kernel memory, aka a write_mmio stack-based out-of-bounds read, related to
    arch/x86/kvm/x86.c and include/trace/events/kvm.h. (CVE-2017-17741)

  - The xfs_bmap_extents_to_btree function in fs/xfs/libxfs/xfs_bmap.c in the Linux kernel through 4.16.3
    allows local users to cause a denial of service (xfs_bmapi_write NULL pointer dereference) via a crafted
    xfs image. (CVE-2018-10323)

  - System software utilizing Lazy FP state restore technique on systems using Intel Core-based
    microprocessors may potentially allow a local process to infer data from another process through a
    speculative execution side channel. (CVE-2018-3665)

  - The snd_seq_ioctl_remove_events function in sound/core/seq/seq_clientmgr.c in the Linux kernel before
    4.4.1 does not verify FIFO assignment before proceeding with FIFO clearing, which allows local users to
    cause a denial of service (NULL pointer dereference and OOPS) via a crafted ioctl call. (CVE-2016-2543)

  - sound/core/hrtimer.c in the Linux kernel before 4.4.1 does not prevent recursive callback access, which
    allows local users to cause a denial of service (deadlock) via a crafted ioctl call. (CVE-2016-2549)

  - Race condition in the queue_delete function in sound/core/seq/seq_queue.c in the Linux kernel before 4.4.1
    allows local users to cause a denial of service (use-after-free and system crash) by making an ioctl call
    at a certain time. (CVE-2016-2544)

  - The snd_timer_interrupt function in sound/core/timer.c in the Linux kernel before 4.4.1 does not properly
    maintain a certain linked list, which allows local users to cause a denial of service (race condition and
    system crash) via a crafted ioctl call. (CVE-2016-2545)

  - sound/core/timer.c in the Linux kernel before 4.4.1 employs a locking approach that does not consider
    slave timer instances, which allows local users to cause a denial of service (race condition, use-after-
    free, and system crash) via a crafted ioctl call. (CVE-2016-2547)

  - sound/core/timer.c in the Linux kernel before 4.4.1 retains certain linked lists after a close or stop
    action, which allows local users to cause a denial of service (system crash) via a crafted ioctl call,
    related to the (1) snd_timer_close and (2) _snd_timer_stop functions. (CVE-2016-2548)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2018-4134.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1000410");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-118.21.4.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-118.21.4.el7uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6 / 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['3.8.13-118.21.4.el6uek', '3.8.13-118.21.4.el7uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2018-4134');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '3.8';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'dtrace-modules-3.8.13-118.21.4.el6uek-0.4.5-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-3.8.13-118.21.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-3.8.13'},
    {'reference':'kernel-uek-debug-3.8.13-118.21.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-3.8.13'},
    {'reference':'kernel-uek-debug-devel-3.8.13-118.21.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-3.8.13'},
    {'reference':'kernel-uek-devel-3.8.13-118.21.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-3.8.13'},
    {'reference':'kernel-uek-doc-3.8.13-118.21.4.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-3.8.13'},
    {'reference':'kernel-uek-firmware-3.8.13-118.21.4.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-3.8.13'},
    {'reference':'dtrace-modules-3.8.13-118.21.4.el7uek-0.4.5-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-3.8.13-118.21.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-3.8.13'},
    {'reference':'kernel-uek-debug-3.8.13-118.21.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-3.8.13'},
    {'reference':'kernel-uek-debug-devel-3.8.13-118.21.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-3.8.13'},
    {'reference':'kernel-uek-devel-3.8.13-118.21.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-3.8.13'},
    {'reference':'kernel-uek-doc-3.8.13-118.21.4.el7uek', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-3.8.13'},
    {'reference':'kernel-uek-firmware-3.8.13-118.21.4.el7uek', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-3.8.13'}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dtrace-modules-3.8.13-118.21.4.el6uek / dtrace-modules-3.8.13-118.21.4.el7uek / kernel-uek / etc');
}
