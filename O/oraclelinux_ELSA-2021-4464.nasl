#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-4464.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155416);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/25");

  script_cve_id("CVE-2021-3445");

  script_name(english:"Oracle Linux 8 : dnf (ELSA-2021-4464)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2021-4464 advisory.

  - A flaw was found in libdnf's signature verification functionality in versions before 0.60.1. This flaw
    allows an attacker to achieve code execution if they can alter the header information of an RPM package
    and then trick a user or system into installing it. The highest risk of this vulnerability is to
    confidentiality, integrity, as well as system availability. (CVE-2021-3445)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-4464.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3445");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dnf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dnf-automatic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dnf-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dnf-plugins-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libdnf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libdnf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-dnf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-dnf-plugin-post-transaction-actions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-dnf-plugin-versionlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-dnf-plugins-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-hawkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-libdnf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-utils");
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
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'dnf-4.7.0-4.0.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dnf-automatic-4.7.0-4.0.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dnf-data-4.7.0-4.0.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dnf-plugins-core-4.0.21-3.0.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdnf-0.63.0-3.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdnf-0.63.0-3.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdnf-0.63.0-3.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdnf-devel-0.63.0-3.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdnf-devel-0.63.0-3.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdnf-devel-0.63.0-3.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-dnf-4.7.0-4.0.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-dnf-plugin-post-transaction-actions-4.0.21-3.0.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-dnf-plugin-versionlock-4.0.21-3.0.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-dnf-plugins-core-4.0.21-3.0.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-hawkey-0.63.0-3.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-hawkey-0.63.0-3.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libdnf-0.63.0-3.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libdnf-0.63.0-3.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-4.7.0-4.0.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-utils-4.0.21-3.0.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dnf / dnf-automatic / dnf-data / etc');
}
