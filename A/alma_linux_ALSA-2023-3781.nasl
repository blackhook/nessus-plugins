#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2023:3781.
##

include('compat.inc');

if (description)
{
  script_id(177616);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/26");

  script_cve_id("CVE-2023-24329");
  script_xref(name:"ALSA", value:"2023:3781");

  script_name(english:"AlmaLinux 8 : python38:3.8 and python38-devel:3.8 (ALSA-2023:3781)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by a vulnerability as referenced in the
ALSA-2023:3781 advisory.

  - An issue in the urllib.parse component of Python before 3.11.4 allows attackers to bypass blocklisting
    methods by supplying a URL that starts with blank characters. (CVE-2023-24329)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2023-3781.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24329");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-Cython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-asn1crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-atomicwrites");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-attrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-cffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-markupsafe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-mod_wsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-more-itertools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-numpy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-numpy-f2py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-packaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-pip-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-pluggy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-ply");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-psutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-psycopg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-psycopg2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-psycopg2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-pycparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-pyparsing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-pysocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-pytest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-pytz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-pyyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-scipy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-setuptools-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-six");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-wcwidth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python38-wheel-wheel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::powertools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var module_ver = get_kb_item('Host/AlmaLinux/appstream/python38-devel');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python38-devel:3.8');
if ('3.8' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module python38-devel:' + module_ver);

var appstreams = {
    'python38-devel:3.8': [
      {'reference':'python38-asn1crypto-1.2.0-3.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-atomicwrites-1.3.0-8.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-attrs-19.3.0-3.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-babel-2.7.0-11.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-cffi-1.13.2-3.module_el8.6.0+2778+cd494b30', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-cffi-1.13.2-3.module_el8.6.0+2778+cd494b30', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-chardet-3.0.4-19.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-cryptography-2.8-3.module_el8.6.0+2778+cd494b30', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-cryptography-2.8-3.module_el8.6.0+2778+cd494b30', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-Cython-0.29.14-4.module_el8.6.0+2778+cd494b30', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-Cython-0.29.14-4.module_el8.6.0+2778+cd494b30', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-idna-2.8-6.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-jinja2-2.11.3-1.module_el8.7.0+3344+99a6a656', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-lxml-4.4.1-7.module_el8.6.0+2778+cd494b30', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-lxml-4.4.1-7.module_el8.6.0+2778+cd494b30', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-markupsafe-1.1.1-6.module_el8.6.0+2778+cd494b30', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-markupsafe-1.1.1-6.module_el8.6.0+2778+cd494b30', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-mod_wsgi-4.6.8-4.module_el8.7.0+3344+99a6a656', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-mod_wsgi-4.6.8-4.module_el8.7.0+3344+99a6a656', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-more-itertools-7.2.0-5.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-numpy-1.17.3-6.module_el8.6.0+2778+cd494b30', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-numpy-1.17.3-6.module_el8.6.0+2778+cd494b30', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-numpy-doc-1.17.3-6.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-numpy-f2py-1.17.3-6.module_el8.6.0+2778+cd494b30', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-numpy-f2py-1.17.3-6.module_el8.6.0+2778+cd494b30', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-packaging-19.2-3.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pip-19.3.1-6.module_el8.7.0+3344+99a6a656', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pip-wheel-19.3.1-6.module_el8.7.0+3344+99a6a656', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pluggy-0.13.0-3.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-ply-3.11-10.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-psutil-5.6.4-4.module_el8.6.0+2778+cd494b30', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-psutil-5.6.4-4.module_el8.6.0+2778+cd494b30', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-psycopg2-2.8.4-4.module_el8.6.0+2778+cd494b30', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-psycopg2-2.8.4-4.module_el8.6.0+2778+cd494b30', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-psycopg2-doc-2.8.4-4.module_el8.6.0+2778+cd494b30', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-psycopg2-doc-2.8.4-4.module_el8.6.0+2778+cd494b30', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-psycopg2-tests-2.8.4-4.module_el8.6.0+2778+cd494b30', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-psycopg2-tests-2.8.4-4.module_el8.6.0+2778+cd494b30', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-py-1.8.0-8.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pycparser-2.19-3.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-PyMySQL-0.10.1-1.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pyparsing-2.4.5-3.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pysocks-1.7.1-4.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pytest-4.6.6-3.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pytz-2019.3-3.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pyyaml-5.4.1-1.module_el8.6.0+2778+cd494b30', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pyyaml-5.4.1-1.module_el8.6.0+2778+cd494b30', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-requests-2.22.0-9.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-scipy-1.3.1-4.module_el8.6.0+2778+cd494b30', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-scipy-1.3.1-4.module_el8.6.0+2778+cd494b30', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-setuptools-41.6.0-5.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-setuptools-wheel-41.6.0-5.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-six-1.12.0-10.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-urllib3-1.25.7-5.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-wcwidth-0.1.7-16.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-wheel-0.33.6-6.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-wheel-wheel-0.33.6-6.module_el8.6.0+2778+cd494b30', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/AlmaLinux/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      var exists_check = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
      if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python38-devel:3.8');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python38-Cython / python38-PyMySQL / python38-asn1crypto / etc');
}
