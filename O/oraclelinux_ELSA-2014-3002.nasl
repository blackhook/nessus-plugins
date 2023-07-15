#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2014-3002.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72472);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/08");

  script_cve_id(
    "CVE-2013-0343",
    "CVE-2013-2147",
    "CVE-2013-2148",
    "CVE-2013-2850",
    "CVE-2013-2888",
    "CVE-2013-2889",
    "CVE-2013-2892",
    "CVE-2013-2893",
    "CVE-2013-2895",
    "CVE-2013-2896",
    "CVE-2013-2897",
    "CVE-2013-2898",
    "CVE-2013-2899",
    "CVE-2013-4299",
    "CVE-2013-4345",
    "CVE-2013-4350",
    "CVE-2013-4470",
    "CVE-2013-4592",
    "CVE-2013-6367",
    "CVE-2013-6368",
    "CVE-2013-6376"
  );

  script_name(english:"Oracle Linux 6 : Unbreakable Enterprise kernel (ELSA-2014-3002)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2014-3002 advisory.

  - The HP Smart Array controller disk-array driver and Compaq SMART2 controller disk-array driver in the
    Linux kernel through 3.9.4 do not initialize certain data structures, which allows local users to obtain
    sensitive information from kernel memory via (1) a crafted IDAGETPCIINFO command for a /dev/ida device,
    related to the ida_locked_ioctl function in drivers/block/cpqarray.c or (2) a crafted CCISS_PASSTHRU32
    command for a /dev/cciss device, related to the cciss_ioctl32_passthru function in drivers/block/cciss.c.
    (CVE-2013-2147)

  - The fill_event_metadata function in fs/notify/fanotify/fanotify_user.c in the Linux kernel through 3.9.4
    does not initialize a certain structure member, which allows local users to obtain sensitive information
    from kernel memory via a read operation on the fanotify descriptor. (CVE-2013-2148)

  - Heap-based buffer overflow in the iscsi_add_notunderstood_response function in
    drivers/target/iscsi/iscsi_target_parameters.c in the iSCSI target subsystem in the Linux kernel through
    3.9.4 allows remote attackers to cause a denial of service (memory corruption and OOPS) or possibly
    execute arbitrary code via a long key that is not properly handled during construction of an error-
    response packet. (CVE-2013-2850)

  - The Human Interface Device (HID) subsystem in the Linux kernel through 3.11, when CONFIG_LOGITECH_FF,
    CONFIG_LOGIG940_FF, or CONFIG_LOGIWHEELS_FF is enabled, allows physically proximate attackers to cause a
    denial of service (heap-based out-of-bounds write) via a crafted device, related to (1) drivers/hid/hid-
    lgff.c, (2) drivers/hid/hid-lg3ff.c, and (3) drivers/hid/hid-lg4ff.c. (CVE-2013-2893)

  - drivers/hid/hid-logitech-dj.c in the Human Interface Device (HID) subsystem in the Linux kernel through
    3.11, when CONFIG_HID_LOGITECH_DJ is enabled, allows physically proximate attackers to cause a denial of
    service (NULL pointer dereference and OOPS) or obtain sensitive information from kernel memory via a
    crafted device. (CVE-2013-2895)

  - drivers/hid/hid-ntrig.c in the Human Interface Device (HID) subsystem in the Linux kernel through 3.11,
    when CONFIG_HID_NTRIG is enabled, allows physically proximate attackers to cause a denial of service (NULL
    pointer dereference and OOPS) via a crafted device. (CVE-2013-2896)

  - Multiple array index errors in drivers/hid/hid-multitouch.c in the Human Interface Device (HID) subsystem
    in the Linux kernel through 3.11, when CONFIG_HID_MULTITOUCH is enabled, allow physically proximate
    attackers to cause a denial of service (heap memory corruption, or NULL pointer dereference and OOPS) via
    a crafted device. (CVE-2013-2897)

  - drivers/hid/hid-sensor-hub.c in the Human Interface Device (HID) subsystem in the Linux kernel through
    3.11, when CONFIG_HID_SENSOR_HUB is enabled, allows physically proximate attackers to obtain sensitive
    information from kernel memory via a crafted device. (CVE-2013-2898)

  - drivers/hid/hid-picolcd_core.c in the Human Interface Device (HID) subsystem in the Linux kernel through
    3.11, when CONFIG_HID_PICOLCD is enabled, allows physically proximate attackers to cause a denial of
    service (NULL pointer dereference and OOPS) via a crafted device. (CVE-2013-2899)

  - The IPv6 SCTP implementation in net/sctp/ipv6.c in the Linux kernel through 3.11.1 uses data structures
    and function calls that do not trigger an intended configuration of IPsec encryption, which allows remote
    attackers to obtain sensitive information by sniffing the network. (CVE-2013-4350)

  - Memory leak in the unshare_userns function in kernel/user_namespace.c in the Linux kernel before 3.10.6
    allows local users to cause a denial of service (memory consumption) via an invalid CLONE_NEWUSER unshare
    call. (CVE-2013-4205)

  - Off-by-one error in the build_unc_path_to_root function in fs/cifs/connect.c in the Linux kernel before
    3.9.6 allows remote attackers to cause a denial of service (memory corruption and system crash) via a DFS
    share mount operation that triggers use of an unexpected DFS referral name length. (CVE-2013-4247)

  - The net_ctl_permissions function in net/sysctl_net.c in the Linux kernel before 3.11.5 does not properly
    determine uid and gid values, which allows local users to bypass intended /proc/sys/net restrictions via a
    crafted application. (CVE-2013-4270)

  - The scm_check_creds function in net/core/scm.c in the Linux kernel before 3.11 performs a capability check
    in an incorrect namespace, which allows local users to gain privileges via PID spoofing. (CVE-2013-4300)

  - The fib6_add function in net/ipv6/ip6_fib.c in the Linux kernel before 3.11.5 does not properly implement
    error-code encoding, which allows local users to cause a denial of service (NULL pointer dereference and
    system crash) by leveraging the CAP_NET_ADMIN capability for an IPv6 SIOCADDRT ioctl call. (CVE-2013-6431)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2014-3002.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2850");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-26.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-provider-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-headers");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['3.8.13-26.el6uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2014-3002');
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
    {'reference':'dtrace-modules-3.8.13-26.el6uek-0.4.2-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtrace-modules-headers-0.4.2-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtrace-modules-provider-headers-0.4.2-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-3.8.13-26.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-3.8.13'},
    {'reference':'kernel-uek-debug-3.8.13-26.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-3.8.13'},
    {'reference':'kernel-uek-debug-devel-3.8.13-26.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-3.8.13'},
    {'reference':'kernel-uek-devel-3.8.13-26.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-3.8.13'},
    {'reference':'kernel-uek-doc-3.8.13-26.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-3.8.13'},
    {'reference':'kernel-uek-firmware-3.8.13-26.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-3.8.13'},
    {'reference':'kernel-uek-headers-3.8.13-26.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-headers-3.8.13'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dtrace-modules-3.8.13-26.el6uek / dtrace-modules-headers / dtrace-modules-provider-headers / etc');
}
