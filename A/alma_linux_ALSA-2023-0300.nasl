#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2023:0300.
##

include('compat.inc');

if (description)
{
  script_id(170583);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/26");

  script_cve_id(
    "CVE-2022-2959",
    "CVE-2022-2964",
    "CVE-2022-3077",
    "CVE-2022-4139",
    "CVE-2022-30594",
    "CVE-2022-43945"
  );
  script_xref(name:"ALSA", value:"2023:0300");

  script_name(english:"AlmaLinux 9 : kernel-rt (ALSA-2023:0300)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2023:0300 advisory.

  - A race condition was found in the Linux kernel's watch queue due to a missing lock in pipe_resize_ring().
    The specific flaw exists within the handling of pipe buffers. The issue results from the lack of proper
    locking when performing operations on an object. This flaw allows a local user to crash the system or
    escalate their privileges on the system. (CVE-2022-2959)

  - A flaw was found in the Linux kernel's driver for the ASIX AX88179_178A-based USB 2.0/3.0 Gigabit Ethernet
    Devices. The vulnerability contains multiple out-of-bounds reads and possible out-of-bounds writes.
    (CVE-2022-2964)

  - A buffer overflow vulnerability was found in the Linux kernel Intel's iSMT SMBus host controller driver in
    the way it handled the I2C_SMBUS_BLOCK_PROC_CALL case (via the ioctl I2C_SMBUS) with malicious input data.
    This flaw could allow a local user to crash the system. (CVE-2022-3077)

  - The Linux kernel before 5.17.2 mishandles seccomp permissions. The PTRACE_SEIZE code path allows attackers
    to bypass intended restrictions on setting the PT_SUSPEND_SECCOMP flag. (CVE-2022-30594)

  - The Linux kernel NFSD implementation prior to versions 5.19.17 and 6.0.2 are vulnerable to buffer
    overflow. NFSD tracks the number of pages held by each NFSD thread by combining the receive and send
    buffers of a remote procedure call (RPC) into a single array of pages. A client can force the send buffer
    to shrink by sending an RPC message over TCP with garbage data added at the end of the message. The RPC
    message with garbage data is still correctly formed according to the specification and is passed forward
    to handlers. Vulnerable code in NFSD is not expecting the oversized request and writes beyond the
    allocated buffer space. CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H (CVE-2022-43945)

  - kernel: i915: Incorrect GPU TLB flush can lead to random memory access (CVE-2022-4139)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2023-0300.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30594");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 120, 276, 281, 416, 667, 770);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-modules-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::realtime");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 9.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2022-2959', 'CVE-2022-2964', 'CVE-2022-3077', 'CVE-2022-4139', 'CVE-2022-30594', 'CVE-2022-43945');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ALSA-2023:0300');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}
var pkgs = [
    {'reference':'kernel-rt-5.14.0-162.12.1.rt21.175.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-core-5.14.0-162.12.1.rt21.175.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-5.14.0-162.12.1.rt21.175.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-core-5.14.0-162.12.1.rt21.175.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-devel-5.14.0-162.12.1.rt21.175.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-kvm-5.14.0-162.12.1.rt21.175.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-5.14.0-162.12.1.rt21.175.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-extra-5.14.0-162.12.1.rt21.175.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-devel-5.14.0-162.12.1.rt21.175.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-kvm-5.14.0-162.12.1.rt21.175.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-5.14.0-162.12.1.rt21.175.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-extra-5.14.0-162.12.1.rt21.175.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-rt / kernel-rt-core / kernel-rt-debug / kernel-rt-debug-core / etc');
}
