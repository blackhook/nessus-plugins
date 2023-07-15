##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2022:1851.
##

include('compat.inc');

if (description)
{
  script_id(161103);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2021-4213");
  script_xref(name:"ALSA", value:"2022:1851");

  script_name(english:"AlmaLinux 8 : pki-core:10.6 (ALSA-2022:1851)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by a vulnerability as referenced in the
ALSA-2022:1851 advisory.

  - A flaw was found in JSS, where it did not properly free up all memory. Over time, the wasted memory builds
    up in the server memory, saturating the server's RAM. This flaw allows an attacker to force the invocation
    of an out-of-memory process, causing a denial of service. (CVE-2021-4213)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2022-1851.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4213");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:jss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:jss-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ldapjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ldapjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pki-acme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pki-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pki-base-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pki-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pki-kra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pki-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pki-symkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pki-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-pki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:tomcatjss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


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

var module_ver = get_kb_item('Host/AlmaLinux/appstream/pki-core');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module pki-core:10.6');
if ('10.6' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module pki-core:' + module_ver);

var appstreams = {
    'pki-core:10.6': [
      {'reference':'jss-4.9.3-1.module_el8.6.0+2764+9fc58d50', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jss-javadoc-4.9.3-1.module_el8.6.0+2764+9fc58d50', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ldapjdk-4.23.0-1.module_el8.6.0+2764+9fc58d50', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ldapjdk-javadoc-4.23.0-1.module_el8.6.0+2764+9fc58d50', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-acme-10.12.0-2.module_el8.6.0+2764+9fc58d50', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-base-10.12.0-2.module_el8.6.0+2764+9fc58d50', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-base-java-10.12.0-2.module_el8.6.0+2764+9fc58d50', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-ca-10.12.0-2.module_el8.6.0+2764+9fc58d50', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-kra-10.12.0-2.module_el8.6.0+2764+9fc58d50', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-server-10.12.0-2.module_el8.6.0+2764+9fc58d50', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-symkey-10.12.0-2.module_el8.6.0+2764+9fc58d50', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-tools-10.12.0-2.module_el8.6.0+2764+9fc58d50', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pki-10.12.0-2.module_el8.6.0+2764+9fc58d50', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tomcatjss-7.7.1-1.module_el8.6.0+2764+9fc58d50', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jss-4.9.3-1.module_el8.6.0+2764+9fc58d50', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jss-javadoc-4.9.3-1.module_el8.6.0+2764+9fc58d50', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-symkey-10.12.0-2.module_el8.6.0+2764+9fc58d50', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-tools-10.12.0-2.module_el8.6.0+2764+9fc58d50', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module pki-core:10.6');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jss / jss-javadoc / ldapjdk / ldapjdk-javadoc / pki-acme / pki-base / etc');
}
