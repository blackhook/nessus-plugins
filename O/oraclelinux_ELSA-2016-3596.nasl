#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2016-3596.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93148);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/08");

  script_cve_id(
    "CVE-2013-4312",
    "CVE-2015-7513",
    "CVE-2015-7799",
    "CVE-2015-7837",
    "CVE-2015-8767",
    "CVE-2015-8785",
    "CVE-2015-8787",
    "CVE-2015-8816",
    "CVE-2016-0723",
    "CVE-2016-0758",
    "CVE-2016-2069",
    "CVE-2016-2085",
    "CVE-2016-2117",
    "CVE-2016-2847",
    "CVE-2016-3136",
    "CVE-2016-3137",
    "CVE-2016-3156",
    "CVE-2016-3157",
    "CVE-2016-4470",
    "CVE-2016-4565",
    "CVE-2016-4581",
    "CVE-2016-4805",
    "CVE-2016-4913",
    "CVE-2016-4951",
    "CVE-2016-6197",
    "CVE-2016-6198"
  );

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2016-3596)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2016-3596 advisory.

  - The fuse_fill_write_pages function in fs/fuse/file.c in the Linux kernel before 4.4 allows local users to
    cause a denial of service (infinite loop) via a writev system call that triggers a zero length for the
    first segment of an iov. (CVE-2015-8785)

  - The hub_activate function in drivers/usb/core/hub.c in the Linux kernel before 4.3.5 does not properly
    maintain a hub-interface data structure, which allows physically proximate attackers to cause a denial of
    service (invalid memory access and system crash) or possibly have unspecified other impact by unplugging a
    USB hub device. (CVE-2015-8816)

  - Race condition in arch/x86/mm/tlb.c in the Linux kernel before 4.4.1 allows local users to gain privileges
    by triggering access to a paging structure by a different CPU. (CVE-2016-2069)

  - The IPv4 implementation in the Linux kernel before 4.5.2 mishandles destruction of device objects, which
    allows guest OS users to cause a denial of service (host OS networking outage) by arranging for a large
    number of IP addresses. (CVE-2016-3156)

  - fs/pnode.c in the Linux kernel before 4.5.4 does not properly traverse a mount propagation tree in a
    certain case involving a slave mount, which allows local users to cause a denial of service (NULL pointer
    dereference and OOPS) via a crafted series of mount system calls. (CVE-2016-4581)

  - Use-after-free vulnerability in drivers/net/ppp/ppp_generic.c in the Linux kernel before 4.5.2 allows
    local users to cause a denial of service (memory corruption and system crash, or spinlock) or possibly
    have unspecified other impact by removing a network namespace, related to the ppp_register_net_channel and
    ppp_unregister_channel functions. (CVE-2016-4805)

  - The get_rock_ridge_filename function in fs/isofs/rock.c in the Linux kernel before 4.5.5 mishandles NM
    (aka alternate name) entries containing \0 characters, which allows local users to obtain sensitive
    information from kernel memory or possibly have unspecified other impact via a crafted isofs filesystem.
    (CVE-2016-4913)

  - The tipc_nl_publ_dump function in net/tipc/socket.c in the Linux kernel through 4.6 does not verify socket
    existence, which allows local users to cause a denial of service (NULL pointer dereference and system
    crash) or possibly have unspecified other impact via a dumpit operation. (CVE-2016-4951)

  - The nf_nat_redirect_ipv4 function in net/netfilter/nf_nat_redirect.c in the Linux kernel before 4.4 allows
    remote attackers to cause a denial of service (NULL pointer dereference and system crash) or possibly have
    unspecified other impact by sending certain IPv4 packets to an incompletely configured interface, a
    related issue to CVE-2003-1604. (CVE-2015-8787)

  - Race condition in the tty_ioctl function in drivers/tty/tty_io.c in the Linux kernel through 4.4.1 allows
    local users to obtain sensitive information from kernel memory or cause a denial of service (use-after-
    free and system crash) by making a TIOCGETD ioctl call during processing of a TIOCSETD ioctl call.
    (CVE-2016-0723)

  - fs/pipe.c in the Linux kernel before 4.5 does not limit the amount of unread data in pipes, which allows
    local users to cause a denial of service (memory consumption) by creating many pipes with non-default
    sizes. (CVE-2016-2847)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2016-3596.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8787");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-4.1.12-61.1.6.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-4.1.12-61.1.6.el7uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
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
  var fixed_uptrack_levels = ['4.1.12-61.1.6.el6uek', '4.1.12-61.1.6.el7uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2016-3596');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '4.1';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'dtrace-modules-4.1.12-61.1.6.el6uek-0.5.3-2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-4.1.12-61.1.6.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.1.12'},
    {'reference':'kernel-uek-debug-4.1.12-61.1.6.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.1.12'},
    {'reference':'kernel-uek-debug-devel-4.1.12-61.1.6.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.1.12'},
    {'reference':'kernel-uek-devel-4.1.12-61.1.6.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.1.12'},
    {'reference':'kernel-uek-doc-4.1.12-61.1.6.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.1.12'},
    {'reference':'kernel-uek-firmware-4.1.12-61.1.6.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-4.1.12'},
    {'reference':'dtrace-modules-4.1.12-61.1.6.el7uek-0.5.3-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-4.1.12-61.1.6.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.1.12'},
    {'reference':'kernel-uek-debug-4.1.12-61.1.6.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.1.12'},
    {'reference':'kernel-uek-debug-devel-4.1.12-61.1.6.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.1.12'},
    {'reference':'kernel-uek-devel-4.1.12-61.1.6.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.1.12'},
    {'reference':'kernel-uek-doc-4.1.12-61.1.6.el7uek', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.1.12'},
    {'reference':'kernel-uek-firmware-4.1.12-61.1.6.el7uek', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-4.1.12'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dtrace-modules-4.1.12-61.1.6.el6uek / dtrace-modules-4.1.12-61.1.6.el7uek / kernel-uek / etc');
}
