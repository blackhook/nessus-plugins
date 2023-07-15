#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-9285.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150299);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id(
    "CVE-2020-15469",
    "CVE-2020-27821",
    "CVE-2021-3409",
    "CVE-2021-20221"
  );
  script_xref(name:"IAVB", value:"2020-B-0041-S");
  script_xref(name:"IAVB", value:"2020-B-0075-S");

  script_name(english:"Oracle Linux 7 : qemu (ELSA-2021-9285)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-9285 advisory.

  - In QEMU 4.2.0, a MemoryRegionOps object may lack read/write callback methods, leading to a NULL pointer
    dereference. (CVE-2020-15469)

  - A flaw was found in the memory management API of QEMU during the initialization of a memory region cache.
    This issue could lead to an out-of-bounds write access to the MSI-X table while performing MMIO
    operations. A guest user may abuse this flaw to crash the QEMU process on the host, resulting in a denial
    of service. This flaw affects QEMU versions prior to 5.2.0. (CVE-2020-27821)

  - An out-of-bounds heap buffer access issue was found in the ARM Generic Interrupt Controller emulator of
    QEMU up to and including qemu 4.2.0on aarch64 platform. The issue occurs because while writing an
    interrupt ID to the controller memory area, it is not masked to be 4 bits wide. It may lead to the said
    issue while updating controller state fields and their subsequent processing. A privileged guest user may
    use this flaw to crash the QEMU process on the host resulting in DoS scenario. (CVE-2021-20221)

  - The patch for CVE-2020-17380/CVE-2020-25085 was found to be ineffective, thus making QEMU vulnerable to
    the out-of-bounds read/write access issues previously found in the SDHCI controller emulation code. This
    flaw allows a malicious privileged guest to crash the QEMU process on the host, resulting in a denial of
    service or potential code execution. QEMU up to (including) 5.2.0 is affected by this. (CVE-2021-3409)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-9285.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3409");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ivshmem-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-block-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-system-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-system-aarch64-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-system-x86-core");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

pkgs = [
    {'reference':'ivshmem-tools-4.2.1-9.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-4.2.1-9.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-4.2.1-9.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-block-gluster-4.2.1-9.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-block-gluster-4.2.1-9.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-block-iscsi-4.2.1-9.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-block-iscsi-4.2.1-9.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-block-rbd-4.2.1-9.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-block-rbd-4.2.1-9.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-common-4.2.1-9.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-common-4.2.1-9.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-img-4.2.1-9.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-img-4.2.1-9.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-4.2.1-9.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-4.2.1-9.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-core-4.2.1-9.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-core-4.2.1-9.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-system-aarch64-4.2.1-9.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-system-aarch64-core-4.2.1-9.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-system-x86-4.2.1-9.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-system-x86-core-4.2.1-9.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  rpm_prefix = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['rpm_prefix'])) rpm_prefix = package_array['rpm_prefix'];
  if (reference && release) {
    if (rpm_prefix) {
        if (rpm_exists(release:release, rpm:rpm_prefix) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ivshmem-tools / qemu / qemu-block-gluster / etc');
}
