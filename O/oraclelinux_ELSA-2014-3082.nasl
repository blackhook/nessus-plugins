#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2014-3082.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78579);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id(
    "CVE-2013-2596",
    "CVE-2014-3122",
    "CVE-2014-3601",
    "CVE-2014-4653",
    "CVE-2014-4654",
    "CVE-2014-4655",
    "CVE-2014-5077"
  );
  script_bugtraq_id(
    59264,
    67162,
    68162,
    68164,
    68881,
    69489
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/10/06");

  script_name(english:"Oracle Linux 5 / 6 : Unbreakable Enterprise kernel (ELSA-2014-3082)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 / 6 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2014-3082 advisory.

  - sound/core/control.c in the ALSA control implementation in the Linux kernel before 3.15.2 does not ensure
    possession of a read/write lock, which allows local users to cause a denial of service (use-after-free)
    and obtain sensitive information from kernel memory by leveraging /dev/snd/controlCX access.
    (CVE-2014-4653)

  - The snd_ctl_elem_add function in sound/core/control.c in the ALSA control implementation in the Linux
    kernel before 3.15.2 does not check authorization for SNDRV_CTL_IOCTL_ELEM_REPLACE commands, which allows
    local users to remove kernel controls and cause a denial of service (use-after-free and system crash) by
    leveraging /dev/snd/controlCX access for an ioctl call. (CVE-2014-4654)

  - The snd_ctl_elem_add function in sound/core/control.c in the ALSA control implementation in the Linux
    kernel before 3.15.2 does not properly maintain the user_ctl_count value, which allows local users to
    cause a denial of service (integer overflow and limit bypass) by leveraging /dev/snd/controlCX access for
    a large number of SNDRV_CTL_IOCTL_ELEM_REPLACE ioctl calls. (CVE-2014-4655)

  - The sctp_assoc_update function in net/sctp/associola.c in the Linux kernel through 3.15.8, when SCTP
    authentication is enabled, allows remote attackers to cause a denial of service (NULL pointer dereference
    and OOPS) by starting to establish an association between two endpoints immediately after an exchange of
    INIT and INIT ACK chunks to establish an earlier association between these endpoints in the opposite
    direction. (CVE-2014-5077)

  - The kvm_iommu_map_pages function in virt/kvm/iommu.c in the Linux kernel through 3.16.1 miscalculates the
    number of pages during the handling of a mapping failure, which allows guest OS users to (1) cause a
    denial of service (host OS memory corruption) or possibly have unspecified other impact by triggering a
    large gfn value or (2) cause a denial of service (host OS memory consumption) by triggering a small gfn
    value that leads to permanently pinned pages. (CVE-2014-3601)

  - The try_to_unmap_cluster function in mm/rmap.c in the Linux kernel before 3.14.3 does not properly
    consider which pages must be locked, which allows local users to cause a denial of service (system crash)
    by triggering a memory-usage pattern that requires removal of page-table mappings. (CVE-2014-3122)

  - Integer overflow in the fb_mmap function in drivers/video/fbmem.c in the Linux kernel before 3.8.9, as
    used in a certain Motorola build of Android 4.1.2 and other products, allows local users to create a read-
    write memory mapping for the entirety of kernel memory, and consequently gain privileges, via crafted
    /dev/graphics/fb0 mmap2 system calls, as demonstrated by the Motochopper pwn program. (CVE-2013-2596)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2014-3082.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2596");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['2.6.39-400.215.11.el5uek', '2.6.39-400.215.11.el6uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2014-3082');
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
    {'reference':'kernel-uek-2.6.39-400.215.11.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.39'},
    {'reference':'kernel-uek-2.6.39-400.215.11.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.39'},
    {'reference':'kernel-uek-debug-2.6.39-400.215.11.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.39'},
    {'reference':'kernel-uek-debug-2.6.39-400.215.11.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.39'},
    {'reference':'kernel-uek-debug-devel-2.6.39-400.215.11.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.39'},
    {'reference':'kernel-uek-debug-devel-2.6.39-400.215.11.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.39'},
    {'reference':'kernel-uek-devel-2.6.39-400.215.11.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.39'},
    {'reference':'kernel-uek-devel-2.6.39-400.215.11.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.39'},
    {'reference':'kernel-uek-doc-2.6.39-400.215.11.el5uek', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-2.6.39'},
    {'reference':'kernel-uek-firmware-2.6.39-400.215.11.el5uek', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-2.6.39'},
    {'reference':'kernel-uek-2.6.39-400.215.11.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.39'},
    {'reference':'kernel-uek-2.6.39-400.215.11.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.39'},
    {'reference':'kernel-uek-debug-2.6.39-400.215.11.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.39'},
    {'reference':'kernel-uek-debug-2.6.39-400.215.11.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.39'},
    {'reference':'kernel-uek-debug-devel-2.6.39-400.215.11.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.39'},
    {'reference':'kernel-uek-debug-devel-2.6.39-400.215.11.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.39'},
    {'reference':'kernel-uek-devel-2.6.39-400.215.11.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.39'},
    {'reference':'kernel-uek-devel-2.6.39-400.215.11.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.39'},
    {'reference':'kernel-uek-doc-2.6.39-400.215.11.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-2.6.39'},
    {'reference':'kernel-uek-firmware-2.6.39-400.215.11.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-2.6.39'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek / kernel-uek-debug / kernel-uek-debug-devel / etc');
}
