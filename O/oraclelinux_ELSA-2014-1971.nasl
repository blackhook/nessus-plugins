#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2014-1971.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79845);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/08");

  script_cve_id(
    "CVE-2013-2929",
    "CVE-2014-1739",
    "CVE-2014-3181",
    "CVE-2014-3182",
    "CVE-2014-3184",
    "CVE-2014-3185",
    "CVE-2014-3186",
    "CVE-2014-3631",
    "CVE-2014-3673",
    "CVE-2014-3687",
    "CVE-2014-3688",
    "CVE-2014-4027",
    "CVE-2014-4652",
    "CVE-2014-4654",
    "CVE-2014-4655",
    "CVE-2014-4656",
    "CVE-2014-5045",
    "CVE-2014-6410"
  );
  script_bugtraq_id(
    64111,
    68048,
    68159,
    68162,
    68163,
    68862,
    69763,
    69768,
    69770,
    69779,
    69781,
    69799,
    70095,
    70743,
    70745,
    70746,
    70766,
    70768,
    70883
  );
  script_xref(name:"RHSA", value:"2014:1971");

  script_name(english:"Oracle Linux 7 : kernel (ELSA-2014-1971)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2014-1971 advisory.

  - The Linux kernel before 3.12.2 does not properly use the get_dumpable function, which allows local users
    to bypass intended ptrace restrictions or obtain sensitive information from IA64 scratch registers via a
    crafted application, related to kernel/ptrace.c and arch/ia64/include/asm/processor.h. (CVE-2013-2929)

  - The snd_ctl_elem_add function in sound/core/control.c in the ALSA control implementation in the Linux
    kernel before 3.15.2 does not check authorization for SNDRV_CTL_IOCTL_ELEM_REPLACE commands, which allows
    local users to remove kernel controls and cause a denial of service (use-after-free and system crash) by
    leveraging /dev/snd/controlCX access for an ioctl call. (CVE-2014-4654)

  - The snd_ctl_elem_add function in sound/core/control.c in the ALSA control implementation in the Linux
    kernel before 3.15.2 does not properly maintain the user_ctl_count value, which allows local users to
    cause a denial of service (integer overflow and limit bypass) by leveraging /dev/snd/controlCX access for
    a large number of SNDRV_CTL_IOCTL_ELEM_REPLACE ioctl calls. (CVE-2014-4655)

  - The mountpoint_last function in fs/namei.c in the Linux kernel before 3.15.8 does not properly maintain a
    certain reference count during attempts to use the umount system call in conjunction with a symlink, which
    allows local users to cause a denial of service (memory consumption or use-after-free) or possibly have
    unspecified other impact via the umount program. (CVE-2014-5045)

  - Multiple buffer overflows in the command_port_read_callback function in drivers/usb/serial/whiteheat.c in
    the Whiteheat USB Serial Driver in the Linux kernel before 3.16.2 allow physically proximate attackers to
    execute arbitrary code or cause a denial of service (memory corruption and system crash) via a crafted
    device that provides a large amount of (1) EHCI or (2) XHCI data associated with a bulk response.
    (CVE-2014-3185)

  - Multiple stack-based buffer overflows in the magicmouse_raw_event function in drivers/hid/hid-magicmouse.c
    in the Magic Mouse HID driver in the Linux kernel through 3.16.3 allow physically proximate attackers to
    cause a denial of service (system crash) or possibly execute arbitrary code via a crafted device that
    provides a large amount of (1) EHCI or (2) XHCI data associated with an event. (CVE-2014-3181)

  - The sctp_assoc_lookup_asconf_ack function in net/sctp/associola.c in the SCTP implementation in the Linux
    kernel through 3.17.2 allows remote attackers to cause a denial of service (panic) via duplicate ASCONF
    chunks that trigger an incorrect uncork within the side-effect interpreter. (CVE-2014-3687)

  - The SCTP implementation in the Linux kernel through 3.17.2 allows remote attackers to cause a denial of
    service (system crash) via a malformed ASCONF chunk, related to net/sctp/sm_make_chunk.c and
    net/sctp/sm_statefuns.c. (CVE-2014-3673)

  - The report_fixup functions in the HID subsystem in the Linux kernel before 3.16.2 might allow physically
    proximate attackers to cause a denial of service (out-of-bounds write) via a crafted device that provides
    a small report descriptor, related to (1) drivers/hid/hid-cherry.c, (2) drivers/hid/hid-kye.c, (3)
    drivers/hid/hid-lg.c, (4) drivers/hid/hid-monterey.c, (5) drivers/hid/hid-petalynx.c, and (6)
    drivers/hid/hid-sunplus.c. (CVE-2014-3184)

  - The media_device_enum_entities function in drivers/media/media-device.c in the Linux kernel before 3.14.6
    does not initialize a certain data structure, which allows local users to obtain sensitive information
    from kernel memory by leveraging /dev/media0 read access for a MEDIA_IOC_ENUM_ENTITIES ioctl call.
    (CVE-2014-1739)

  - Array index error in the logi_dj_raw_event function in drivers/hid/hid-logitech-dj.c in the Linux kernel
    before 3.16.2 allows physically proximate attackers to execute arbitrary code or cause a denial of service
    (invalid kfree) via a crafted device that provides a malformed REPORT_TYPE_NOTIF_DEVICE_UNPAIRED value.
    (CVE-2014-3182)

  - Buffer overflow in the picolcd_raw_event function in devices/hid/hid-picolcd_core.c in the PicoLCD HID
    device driver in the Linux kernel through 3.16.3, as used in Android on Nexus 7 devices, allows physically
    proximate attackers to cause a denial of service (system crash) or possibly execute arbitrary code via a
    crafted device that sends a large report. (CVE-2014-3186)

  - The assoc_array_gc function in the associative-array implementation in lib/assoc_array.c in the Linux
    kernel before 3.16.3 does not properly implement garbage collection, which allows local users to cause a
    denial of service (NULL pointer dereference and system crash) or possibly have unspecified other impact
    via multiple keyctl newring operations followed by a keyctl timeout operation. (CVE-2014-3631)

  - The SCTP implementation in the Linux kernel before 3.17.4 allows remote attackers to cause a denial of
    service (memory consumption) by triggering a large number of chunks in an association's output queue, as
    demonstrated by ASCONF probes, related to net/sctp/inqueue.c and net/sctp/sm_statefuns.c. (CVE-2014-3688)

  - The rd_build_device_space function in drivers/target/target_core_rd.c in the Linux kernel before 3.14 does
    not properly initialize a certain data structure, which allows local users to obtain sensitive information
    from ramdisk_mcp memory by leveraging access to a SCSI initiator. (CVE-2014-4027)

  - Race condition in the tlv handler functionality in the snd_ctl_elem_user_tlv function in
    sound/core/control.c in the ALSA control implementation in the Linux kernel before 3.15.2 allows local
    users to obtain sensitive information from kernel memory by leveraging /dev/snd/controlCX access.
    (CVE-2014-4652)

  - Multiple integer overflows in sound/core/control.c in the ALSA control implementation in the Linux kernel
    before 3.15.2 allow local users to cause a denial of service by leveraging /dev/snd/controlCX access,
    related to (1) index values in the snd_ctl_add function and (2) numid values in the
    snd_ctl_remove_numid_conflict function. (CVE-2014-4656)

  - The __udf_read_inode function in fs/udf/inode.c in the Linux kernel through 3.16.3 does not restrict the
    amount of ICB indirection, which allows physically proximate attackers to cause a denial of service
    (infinite loop or stack consumption) via a UDF filesystem with a crafted inode. (CVE-2014-6410)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2014-1971.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3631");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/10");

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
  var fixed_uptrack_levels = ['3.10.0-123.13.1.el7'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2014-1971');
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
    {'reference':'kernel-3.10.0-123.13.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-3.10.0'},
    {'reference':'kernel-abi-whitelists-3.10.0-123.13.1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-3.10.0'},
    {'reference':'kernel-debug-3.10.0-123.13.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-3.10.0'},
    {'reference':'kernel-debug-devel-3.10.0-123.13.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-3.10.0'},
    {'reference':'kernel-devel-3.10.0-123.13.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-3.10.0'},
    {'reference':'kernel-headers-3.10.0-123.13.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-3.10.0'},
    {'reference':'kernel-tools-3.10.0-123.13.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-3.10.0'},
    {'reference':'kernel-tools-libs-3.10.0-123.13.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-3.10.0'},
    {'reference':'kernel-tools-libs-devel-3.10.0-123.13.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-3.10.0'},
    {'reference':'perf-3.10.0-123.13.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-3.10.0-123.13.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
