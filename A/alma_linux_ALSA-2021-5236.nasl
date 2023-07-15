#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2021:5236.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158869);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id("CVE-2021-3677", "CVE-2021-23214");
  script_xref(name:"ALSA", value:"2021:5236");
  script_xref(name:"IAVB", value:"2021-B-0048-S");
  script_xref(name:"IAVB", value:"2021-B-0067-S");

  script_name(english:"AlmaLinux 8 : postgresql:13 (ALSA-2021:5236)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2021:5236 advisory.

  - A flaw was found in postgresql. A purpose-crafted query can read arbitrary bytes of server memory. In the
    default configuration, any authenticated database user can complete this attack at will. The attack does
    not require the ability to create objects. If server settings include max_worker_processes=0, the known
    versions of this attack are infeasible. However, undiscovered variants of the attack may be independent of
    that setting. (CVE-2021-3677)

  - When the server is configured to use trust authentication with a clientcert requirement or to use cert
    authentication, a man-in-the-middle attacker can inject arbitrary SQL queries when a connection is first
    established, despite the use of SSL certificate verification and encryption. (CVE-2021-23214)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2021-5236.html");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pg_repack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pgaudit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgres-decoderbufs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-plpython3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-test-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-upgrade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-upgrade-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/AlmaLinux/release');
if (isnull(release) || 'AlmaLinux' >!< release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var module_ver = get_kb_item('Host/AlmaLinux/appstream/postgresql');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module postgresql:13');
if ('13' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module postgresql:' + module_ver);

var appstreams = {
    'postgresql:13': [
      {'reference':'pg_repack-1.4.6-3.module_el8.5.0+2607+8c0fd184', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pgaudit-1.5.0-1.module_el8.5.0+2607+8c0fd184', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgres-decoderbufs-0.10.0-2.module_el8.5.0+2607+8c0fd184', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-13.5-1.module_el8.5.0+2607+8c0fd184', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-contrib-13.5-1.module_el8.5.0+2607+8c0fd184', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-docs-13.5-1.module_el8.5.0+2607+8c0fd184', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-plperl-13.5-1.module_el8.5.0+2607+8c0fd184', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-plpython3-13.5-1.module_el8.5.0+2607+8c0fd184', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-pltcl-13.5-1.module_el8.5.0+2607+8c0fd184', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-server-13.5-1.module_el8.5.0+2607+8c0fd184', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-server-devel-13.5-1.module_el8.5.0+2607+8c0fd184', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-static-13.5-1.module_el8.5.0+2607+8c0fd184', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-test-13.5-1.module_el8.5.0+2607+8c0fd184', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-test-rpm-macros-13.5-1.module_el8.5.0+2607+8c0fd184', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-upgrade-13.5-1.module_el8.5.0+2607+8c0fd184', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'postgresql-upgrade-devel-13.5-1.module_el8.5.0+2607+8c0fd184', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/AlmaLinux/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach package_array ( appstreams[module] ) {
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
      if (!empty_or_null(package_array['release'])) release = 'Alma-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
      if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module postgresql:13');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pg_repack / pgaudit / postgres-decoderbufs / postgresql / etc');
}
