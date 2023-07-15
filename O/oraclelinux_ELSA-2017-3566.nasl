#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2017-3566.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100234);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/08");

  script_cve_id(
    "CVE-2015-5257",
    "CVE-2015-6252",
    "CVE-2015-9731",
    "CVE-2016-2782",
    "CVE-2016-7910",
    "CVE-2016-8399",
    "CVE-2016-9644",
    "CVE-2016-10088",
    "CVE-2016-10142",
    "CVE-2016-10208",
    "CVE-2016-10229",
    "CVE-2017-2583",
    "CVE-2017-2647",
    "CVE-2017-5669",
    "CVE-2017-5986",
    "CVE-2017-6214",
    "CVE-2017-7184",
    "CVE-2017-7187",
    "CVE-2017-7895"
  );

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2017-3566)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2017-3566 advisory.

  - The load_segment_descriptor implementation in arch/x86/kvm/emulate.c in the Linux kernel before 4.9.5
    improperly emulates a MOV SS, NULL selector instruction, which allows guest OS users to cause a denial
    of service (guest OS crash) or gain guest OS privileges via a crafted application. (CVE-2017-2583)

  - The tcp_splice_read function in net/ipv4/tcp.c in the Linux kernel before 4.9.11 allows remote attackers
    to cause a denial of service (infinite loop and soft lockup) via vectors involving a TCP packet with the
    URG flag. (CVE-2017-6214)

  - The xfrm_replay_verify_len function in net/xfrm/xfrm_user.c in the Linux kernel through 4.10.6 does not
    validate certain size data after an XFRM_MSG_NEWAE update, which allows local users to obtain root
    privileges or cause a denial of service (heap-based out-of-bounds access) by leveraging the CAP_NET_ADMIN
    capability, as demonstrated during a Pwn2Own competition at CanSecWest 2017 for the Ubuntu 16.10 linux-
    image-* package 4.8.0.41.52. (CVE-2017-7184)

  - The ext4_fill_super function in fs/ext4/super.c in the Linux kernel through 4.9.8 does not properly
    validate meta block groups, which allows physically proximate attackers to cause a denial of service (out-
    of-bounds read and system crash) via a crafted ext4 image. (CVE-2016-10208)

  - Race condition in the sctp_wait_for_sndbuf function in net/sctp/socket.c in the Linux kernel before 4.9.11
    allows local users to cause a denial of service (assertion failure and panic) via a multithreaded
    application that peels off an association in a certain buffer-full state. (CVE-2017-5986)

  - The NFSv2 and NFSv3 server implementations in the Linux kernel through 4.10.13 lack certain checks for the
    end of a buffer, which allows remote attackers to trigger pointer-arithmetic errors or possibly have
    unspecified other impact via crafted requests, related to fs/nfsd/nfs3xdr.c and fs/nfsd/nfsxdr.c.
    (CVE-2017-7895)

  - The vhost_dev_ioctl function in drivers/vhost/vhost.c in the Linux kernel before 4.1.5 allows local users
    to cause a denial of service (memory consumption) via a VHOST_SET_LOG_FD ioctl call that triggers
    permanent file-descriptor allocation. (CVE-2015-6252)

  - The KEYS subsystem in the Linux kernel before 3.18 allows local users to gain privileges or cause a denial
    of service (NULL pointer dereference and system crash) via vectors involving a NULL value for a certain
    match field, related to the keyring_search_iterator function in keyring.c. (CVE-2017-2647)

  - drivers/usb/serial/whiteheat.c in the Linux kernel before 4.2.4 allows physically proximate attackers to
    cause a denial of service (NULL pointer dereference and OOPS) or possibly have unspecified other impact
    via a crafted USB device. NOTE: this ID was incorrectly used for an Apache Cordova issue that has the
    correct ID of CVE-2015-8320. (CVE-2015-5257)

  - The treo_attach function in drivers/usb/serial/visor.c in the Linux kernel before 4.5 allows physically
    proximate attackers to cause a denial of service (NULL pointer dereference and system crash) or possibly
    have unspecified other impact by inserting a USB device that lacks a (1) bulk-in or (2) interrupt-in
    endpoint. (CVE-2016-2782)

  - The do_shmat function in ipc/shm.c in the Linux kernel through 4.9.12 does not restrict the address
    calculated by a certain rounding operation, which allows local users to map page zero, and consequently
    bypass a protection mechanism that exists for the mmap system call, by making crafted shmget and shmat
    system calls in a privileged context. (CVE-2017-5669)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2017-3566.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7895");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-118.18.2.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-118.18.2.el7uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var fixed_uptrack_levels = ['3.8.13-118.18.2.el6uek', '3.8.13-118.18.2.el7uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2017-3566');
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
    {'reference':'dtrace-modules-3.8.13-118.18.2.el6uek-0.4.5-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-3.8.13-118.18.2.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-3.8.13'},
    {'reference':'kernel-uek-debug-3.8.13-118.18.2.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-3.8.13'},
    {'reference':'kernel-uek-debug-devel-3.8.13-118.18.2.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-3.8.13'},
    {'reference':'kernel-uek-devel-3.8.13-118.18.2.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-3.8.13'},
    {'reference':'kernel-uek-doc-3.8.13-118.18.2.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-3.8.13'},
    {'reference':'kernel-uek-firmware-3.8.13-118.18.2.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-3.8.13'},
    {'reference':'dtrace-modules-3.8.13-118.18.2.el7uek-0.4.5-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-3.8.13-118.18.2.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-3.8.13'},
    {'reference':'kernel-uek-debug-3.8.13-118.18.2.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-3.8.13'},
    {'reference':'kernel-uek-debug-devel-3.8.13-118.18.2.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-3.8.13'},
    {'reference':'kernel-uek-devel-3.8.13-118.18.2.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-3.8.13'},
    {'reference':'kernel-uek-doc-3.8.13-118.18.2.el7uek', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-3.8.13'},
    {'reference':'kernel-uek-firmware-3.8.13-118.18.2.el7uek', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-3.8.13'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dtrace-modules-3.8.13-118.18.2.el6uek / dtrace-modules-3.8.13-118.18.2.el7uek / kernel-uek / etc');
}
