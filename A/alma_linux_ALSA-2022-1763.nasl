##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2022:1763.
##

include('compat.inc');

if (description)
{
  script_id(161122);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2021-43818");
  script_xref(name:"ALSA", value:"2022:1763");

  script_name(english:"AlmaLinux 8 : python39:3.9 and python39-devel:3.9 (ALSA-2022:1763)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by a vulnerability as referenced in the
ALSA-2022:1763 advisory.

  - lxml is a library for processing XML and HTML in the Python language. Prior to version 4.6.5, the HTML
    Cleaner in lxml.html lets certain crafted script content pass through, as well as script content in SVG
    files embedded using data URIs. Users that employ the HTML cleaner in a security relevant context should
    upgrade to lxml 4.6.5 to receive a patch. There are no known workarounds available. (CVE-2021-43818)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2022-1763.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43818");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-cffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-mod_wsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-numpy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-numpy-f2py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-pip-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-ply");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-psutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-psycopg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-psycopg2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-psycopg2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-pycparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-pysocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-pyyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-scipy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-setuptools-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-six");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-toml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-wheel-wheel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var module_ver = get_kb_item('Host/AlmaLinux/appstream/python39');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python39:3.9');
if ('3.9' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module python39:' + module_ver);

var appstreams = {
    'python39:3.9': [
      {'reference':'python39-3.9.7-1.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cffi-1.14.3-2.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-chardet-3.0.4-19.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cryptography-3.3.1-2.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-devel-3.9.7-1.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-idle-3.9.7-1.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-idna-2.10-3.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-libs-3.9.7-1.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-lxml-4.6.5-1.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-mod_wsgi-4.7.1-4.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-1.19.4-3.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-doc-1.19.4-3.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-f2py-1.19.4-3.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pip-20.2.4-7.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pip-wheel-20.2.4-7.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-ply-3.11-10.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psutil-5.8.0-4.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-2.8.6-2.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-doc-2.8.6-2.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-tests-2.8.6-2.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pycparser-2.20-3.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-PyMySQL-0.10.1-2.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pysocks-1.7.1-4.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pyyaml-5.4.1-1.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-requests-2.25.0-2.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-rpm-macros-3.9.7-1.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-scipy-1.5.4-3.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-setuptools-50.3.2-4.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-setuptools-wheel-50.3.2-4.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-six-1.15.0-3.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-test-3.9.7-1.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-tkinter-3.9.7-1.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-toml-0.10.1-5.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-urllib3-1.25.10-4.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-wheel-0.35.1-4.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python39-wheel-wheel-0.35.1-4.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python39-3.9.7-1.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cffi-1.14.3-2.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cryptography-3.3.1-2.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-devel-3.9.7-1.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-idle-3.9.7-1.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-libs-3.9.7-1.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-lxml-4.6.5-1.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-mod_wsgi-4.7.1-4.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-1.19.4-3.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-f2py-1.19.4-3.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psutil-5.8.0-4.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-2.8.6-2.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-doc-2.8.6-2.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-tests-2.8.6-2.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pyyaml-5.4.1-1.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-scipy-1.5.4-3.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-test-3.9.7-1.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-tkinter-3.9.7-1.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python39:3.9');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python39 / python39-PyMySQL / python39-cffi / python39-chardet / etc');
}
