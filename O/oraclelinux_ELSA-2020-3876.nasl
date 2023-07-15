##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-3876.
##

include('compat.inc');

if (description)
{
  script_id(141257);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id(
    "CVE-2017-0393",
    "CVE-2019-9232",
    "CVE-2019-9433",
    "CVE-2020-0034"
  );
  script_bugtraq_id(95230);

  script_name(english:"Oracle Linux 7 : libvpx (ELSA-2020-3876)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-3876 advisory.

  - A denial of service vulnerability in libvpx in Mediaserver could enable a remote attacker to use a
    specially crafted file to cause a device hang or reboot. This issue is rated as High due to the
    possibility of remote denial of service. Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0,
    7.1. Android ID: A-30436808. (CVE-2017-0393)

  - In libvpx, there is a possible out of bounds read due to a missing bounds check. This could lead to remote
    information disclosure with no additional execution privileges needed. User interaction is not needed for
    exploitation. Product: AndroidVersions: Android-10Android ID: A-122675483 (CVE-2019-9232)

  - In libvpx, there is a possible information disclosure due to improper input validation. This could lead to
    remote information disclosure with no additional execution privileges needed. User interaction is needed
    for exploitation. Product: AndroidVersions: Android-10Android ID: A-80479354 (CVE-2019-9433)

  - In vp8_decode_frame of decodeframe.c, there is a possible out of bounds read due to improper input
    validation. This could lead to remote information disclosure if error correction were turned on, with no
    additional execution privileges needed. User interaction is not needed for exploitation.Product:
    AndroidVersions: Android-8.0 Android-8.1Android ID: A-62458770 (CVE-2020-0034)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://linux.oracle.com/errata/ELSA-2020-3876.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected libvpx, libvpx-devel and / or libvpx-utils packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0034");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvpx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvpx-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvpx-utils");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'libvpx-1.3.0-8.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvpx-1.3.0-8.el7', 'cpu':'i686', 'release':'7'},
    {'reference':'libvpx-1.3.0-8.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvpx-devel-1.3.0-8.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvpx-devel-1.3.0-8.el7', 'cpu':'i686', 'release':'7'},
    {'reference':'libvpx-devel-1.3.0-8.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'libvpx-utils-1.3.0-8.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'libvpx-utils-1.3.0-8.el7', 'cpu':'x86_64', 'release':'7'}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libvpx / libvpx-devel / libvpx-utils');
}