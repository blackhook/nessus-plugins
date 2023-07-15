#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2011-2015.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68416);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/08");

  script_cve_id(
    "CVE-2010-4565",
    "CVE-2010-4649",
    "CVE-2011-0006",
    "CVE-2011-0711",
    "CVE-2011-0712",
    "CVE-2011-0726",
    "CVE-2011-1013",
    "CVE-2011-1016",
    "CVE-2011-1019",
    "CVE-2011-1044",
    "CVE-2011-1080",
    "CVE-2011-1093",
    "CVE-2011-1573"
  );

  script_name(english:"Oracle Linux 5 / 6 : Unbreakable Enterprise kernel (ELSA-2011-2015)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 / 6 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2011-2015 advisory.

  - The bcm_connect function in net/can/bcm.c (aka the Broadcast Manager) in the Controller Area Network (CAN)
    implementation in the Linux kernel 2.6.36 and earlier creates a publicly accessible file with a filename
    containing a kernel memory address, which allows local users to obtain potentially sensitive information
    about kernel memory use by listing this filename. (CVE-2010-4565)

  - Integer overflow in the ib_uverbs_poll_cq function in drivers/infiniband/core/uverbs_cmd.c in the Linux
    kernel before 2.6.37 allows local users to cause a denial of service (memory corruption) or possibly have
    unspecified other impact via a large value of a certain structure member. (CVE-2010-4649)

  - The ima_lsm_rule_init function in security/integrity/ima/ima_policy.c in the Linux kernel before 2.6.37,
    when the Linux Security Modules (LSM) framework is disabled, allows local users to bypass Integrity
    Measurement Architecture (IMA) rules in opportunistic circumstances by leveraging an administrator's
    addition of an IMA rule for LSM. (CVE-2011-0006)

  - The xfs_fs_geometry function in fs/xfs/xfs_fsops.c in the Linux kernel before 2.6.38-rc6-git3 does not
    initialize a certain structure member, which allows local users to obtain potentially sensitive
    information from kernel stack memory via an FSGEOMETRY_V1 ioctl call. (CVE-2011-0711)

  - Multiple buffer overflows in the caiaq Native Instruments USB audio functionality in the Linux kernel
    before 2.6.38-rc4-next-20110215 might allow attackers to cause a denial of service or possibly have
    unspecified other impact via a long USB device name, related to (1) the snd_usb_caiaq_audio_init function
    in sound/usb/caiaq/audio.c and (2) the snd_usb_caiaq_midi_init function in sound/usb/caiaq/midi.c.
    (CVE-2011-0712)

  - The do_task_stat function in fs/proc/array.c in the Linux kernel before 2.6.39-rc1 does not perform an
    expected uid check, which makes it easier for local users to defeat the ASLR protection mechanism by
    reading the start_code and end_code fields in the /proc/#####/stat file for a process executing a PIE
    binary. (CVE-2011-0726)

  - Integer signedness error in the drm_modeset_ctl function in (1) drivers/gpu/drm/drm_irq.c in the Direct
    Rendering Manager (DRM) subsystem in the Linux kernel before 2.6.38 and (2) sys/dev/pci/drm/drm_irq.c in
    the kernel in OpenBSD before 4.9 allows local users to trigger out-of-bounds write operations, and
    consequently cause a denial of service (system crash) or possibly have unspecified other impact, via a
    crafted num_crtcs (aka vb_num) structure member in an ioctl argument. (CVE-2011-1013)

  - The Radeon GPU drivers in the Linux kernel before 2.6.38-rc5 do not properly validate data related to the
    AA resolve registers, which allows local users to write to arbitrary memory locations associated with (1)
    Video RAM (aka VRAM) or (2) the Graphics Translation Table (GTT) via crafted values. (CVE-2011-1016)

  - The dev_load function in net/core/dev.c in the Linux kernel before 2.6.38 allows local users to bypass an
    intended CAP_SYS_MODULE capability requirement and load arbitrary modules by leveraging the CAP_NET_ADMIN
    capability. (CVE-2011-1019)

  - The ib_uverbs_poll_cq function in drivers/infiniband/core/uverbs_cmd.c in the Linux kernel before 2.6.37
    does not initialize a certain response buffer, which allows local users to obtain potentially sensitive
    information from kernel memory via vectors that cause this buffer to be only partially filled, a different
    vulnerability than CVE-2010-4649. (CVE-2011-1044)

  - The bnep_sock_ioctl function in net/bluetooth/bnep/sock.c in the Linux kernel before 2.6.39 does not
    ensure that a certain device field ends with a '\0' character, which allows local users to obtain
    potentially sensitive information from kernel stack memory, or cause a denial of service (BUG and system
    crash), via a BNEPCONNADD command. (CVE-2011-1079)

  - The do_replace function in net/bridge/netfilter/ebtables.c in the Linux kernel before 2.6.39 does not
    ensure that a certain name field ends with a '\0' character, which allows local users to obtain
    potentially sensitive information from kernel stack memory by leveraging the CAP_NET_ADMIN capability to
    replace a table, and then reading a modprobe command line. (CVE-2011-1080)

  - The dccp_rcv_state_process function in net/dccp/input.c in the Datagram Congestion Control Protocol (DCCP)
    implementation in the Linux kernel before 2.6.38 does not properly handle packets for a CLOSED endpoint,
    which allows remote attackers to cause a denial of service (NULL pointer dereference and OOPS) by sending
    a DCCP-Close packet followed by a DCCP-Reset packet. (CVE-2011-1093)

  - net/sctp/sm_make_chunk.c in the Linux kernel before 2.6.34, when addip_enable and auth_enable are used,
    does not consider the amount of zero padding during calculation of chunk lengths for (1) INIT and (2) INIT
    ACK chunks, which allows remote attackers to cause a denial of service (OOPS) via crafted packet data.
    (CVE-2011-1573)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2011-2015.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-1013");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-100.28.15.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-100.28.15.el5debug");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 5 / 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['2.6.32-100.28.15.el5', '2.6.32-100.28.15.el6'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2011-2015');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '2.6';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-uek-2.6.32-100.28.15.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.32'},
    {'reference':'kernel-uek-debug-2.6.32-100.28.15.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.32'},
    {'reference':'kernel-uek-debug-devel-2.6.32-100.28.15.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.32'},
    {'reference':'kernel-uek-devel-2.6.32-100.28.15.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.32'},
    {'reference':'kernel-uek-doc-2.6.32-100.28.15.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-2.6.32'},
    {'reference':'kernel-uek-firmware-2.6.32-100.28.15.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-2.6.32'},
    {'reference':'kernel-uek-headers-2.6.32-100.28.15.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-headers-2.6.32'},
    {'reference':'ofa-2.6.32-100.28.15.el5-1.5.1-4.0.28', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-100.28.15.el5debug-1.5.1-4.0.28', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-2.6.32-100.28.15.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.32'},
    {'reference':'kernel-uek-debug-2.6.32-100.28.15.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.32'},
    {'reference':'kernel-uek-debug-devel-2.6.32-100.28.15.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.32'},
    {'reference':'kernel-uek-devel-2.6.32-100.28.15.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.32'},
    {'reference':'kernel-uek-doc-2.6.32-100.28.15.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-2.6.32'},
    {'reference':'kernel-uek-firmware-2.6.32-100.28.15.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-2.6.32'},
    {'reference':'kernel-uek-headers-2.6.32-100.28.15.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-headers-2.6.32'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek / kernel-uek-debug / kernel-uek-debug-devel / etc');
}
