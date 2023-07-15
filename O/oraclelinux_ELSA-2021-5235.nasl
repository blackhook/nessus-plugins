#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-5235.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156398);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id("CVE-2021-3677", "CVE-2021-23214");
  script_xref(name:"IAVB", value:"2021-B-0048-S");
  script_xref(name:"IAVB", value:"2021-B-0067-S");

  script_name(english:"Oracle Linux 8 : postgresql:12 (ELSA-2021-5235)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-5235 advisory.

  - postgresql: memory disclosure in certain queries (CVE-2021-3677)

  - postgresql: server processes unencrypted bytes from man-in-the-middle (CVE-2021-23214)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-5235.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23214");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pg_repack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pgaudit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgres-decoderbufs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-plpython3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-test-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-upgrade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-upgrade-devel");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var module_ver = get_kb_item('Host/RedHat/appstream/postgresql');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module postgresql:12');
if ('12' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module postgresql:' + module_ver);

var appstreams = {
    'postgresql:12': [
      {'reference':'pg_repack-1.4.6-3.module+el8.5.0+20333+86306fc7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pg_repack-1.4.6-3.module+el8.5.0+20333+86306fc7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pgaudit-1.4.0-5.module+el8.5.0+20333+86306fc7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pgaudit-1.4.0-5.module+el8.5.0+20333+86306fc7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgres-decoderbufs-0.10.0-2.module+el8.5.0+20333+86306fc7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgres-decoderbufs-0.10.0-2.module+el8.5.0+20333+86306fc7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-12.9-1.module+el8.5.0+20463+3d6b40f2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-12.9-1.module+el8.5.0+20463+3d6b40f2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-contrib-12.9-1.module+el8.5.0+20463+3d6b40f2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-contrib-12.9-1.module+el8.5.0+20463+3d6b40f2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-docs-12.9-1.module+el8.5.0+20463+3d6b40f2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-docs-12.9-1.module+el8.5.0+20463+3d6b40f2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-plperl-12.9-1.module+el8.5.0+20463+3d6b40f2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-plperl-12.9-1.module+el8.5.0+20463+3d6b40f2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-plpython3-12.9-1.module+el8.5.0+20463+3d6b40f2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-plpython3-12.9-1.module+el8.5.0+20463+3d6b40f2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-pltcl-12.9-1.module+el8.5.0+20463+3d6b40f2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-pltcl-12.9-1.module+el8.5.0+20463+3d6b40f2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-server-12.9-1.module+el8.5.0+20463+3d6b40f2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-server-12.9-1.module+el8.5.0+20463+3d6b40f2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-server-devel-12.9-1.module+el8.5.0+20463+3d6b40f2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-server-devel-12.9-1.module+el8.5.0+20463+3d6b40f2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-static-12.9-1.module+el8.5.0+20463+3d6b40f2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-static-12.9-1.module+el8.5.0+20463+3d6b40f2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-test-12.9-1.module+el8.5.0+20463+3d6b40f2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-test-12.9-1.module+el8.5.0+20463+3d6b40f2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-test-rpm-macros-12.9-1.module+el8.5.0+20463+3d6b40f2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-upgrade-12.9-1.module+el8.5.0+20463+3d6b40f2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-upgrade-12.9-1.module+el8.5.0+20463+3d6b40f2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-upgrade-devel-12.9-1.module+el8.5.0+20463+3d6b40f2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-upgrade-devel-12.9-1.module+el8.5.0+20463+3d6b40f2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var release = NULL;
      var sp = NULL;
      var cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && release) {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module postgresql:12');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pg_repack / pgaudit / postgres-decoderbufs / etc');
}
