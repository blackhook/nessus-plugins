#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2022:8492. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(167740);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/06");

  script_cve_id("CVE-2022-42919");
  script_xref(name:"RHSA", value:"2022:8492");
  script_xref(name:"IAVA", value:"2023-A-0061-S");

  script_name(english:"CentOS 8 : python39:3.9 (CESA-2022:8492)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
CESA-2022:8492 advisory.

  - python: local privilege escalation via the multiprocessing forkserver start method (CVE-2022-42919)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:8492");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42919");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-cffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-mod_wsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-numpy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-numpy-f2py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-pip-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-ply");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-psutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-psycopg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-psycopg2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-psycopg2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-pycparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-pysocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-pyyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-scipy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-setuptools-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-six");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-toml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python39-wheel-wheel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS 8-Stream');
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/python39');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python39:3.9');
if ('3.9' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module python39:' + module_ver);

var appstreams = {
    'python39:3.9': [
      {'reference':'python39-cffi-1.14.3-2.module_el8.4.0+680+7b309a77', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cffi-1.14.3-2.module_el8.4.0+680+7b309a77', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-chardet-3.0.4-19.module_el8.4.0+680+7b309a77', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-chardet-3.0.4-19.module_el8.4.0+680+7b309a77', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cryptography-3.3.1-2.module_el8.4.0+680+7b309a77', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cryptography-3.3.1-2.module_el8.4.0+680+7b309a77', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-idna-2.10-3.module_el8.4.0+680+7b309a77', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-idna-2.10-3.module_el8.4.0+680+7b309a77', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-lxml-4.6.5-1.module_el8.6.0+1078+3991166b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-lxml-4.6.5-1.module_el8.6.0+1078+3991166b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-mod_wsgi-4.7.1-5.module_el8.7.0+1213+291b6551', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-mod_wsgi-4.7.1-5.module_el8.7.0+1213+291b6551', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-1.19.4-3.module_el8.5.0+897+68c4c210', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-1.19.4-3.module_el8.5.0+897+68c4c210', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-doc-1.19.4-3.module_el8.5.0+897+68c4c210', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-doc-1.19.4-3.module_el8.5.0+897+68c4c210', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-f2py-1.19.4-3.module_el8.5.0+897+68c4c210', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-f2py-1.19.4-3.module_el8.5.0+897+68c4c210', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pip-20.2.4-7.module_el8.6.0+961+ca697fb5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pip-20.2.4-7.module_el8.6.0+961+ca697fb5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pip-wheel-20.2.4-7.module_el8.6.0+961+ca697fb5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pip-wheel-20.2.4-7.module_el8.6.0+961+ca697fb5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-ply-3.11-10.module_el8.4.0+680+7b309a77', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-ply-3.11-10.module_el8.4.0+680+7b309a77', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psutil-5.8.0-4.module_el8.4.0+680+7b309a77', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psutil-5.8.0-4.module_el8.4.0+680+7b309a77', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-2.8.6-2.module_el8.4.0+680+7b309a77', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-2.8.6-2.module_el8.4.0+680+7b309a77', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-doc-2.8.6-2.module_el8.4.0+680+7b309a77', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-doc-2.8.6-2.module_el8.4.0+680+7b309a77', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-tests-2.8.6-2.module_el8.4.0+680+7b309a77', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-tests-2.8.6-2.module_el8.4.0+680+7b309a77', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pycparser-2.20-3.module_el8.4.0+680+7b309a77', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pycparser-2.20-3.module_el8.4.0+680+7b309a77', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-PyMySQL-0.10.1-2.module_el8.4.0+680+7b309a77', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-PyMySQL-0.10.1-2.module_el8.4.0+680+7b309a77', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pysocks-1.7.1-4.module_el8.4.0+680+7b309a77', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pysocks-1.7.1-4.module_el8.4.0+680+7b309a77', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pyyaml-5.4.1-1.module_el8.5.0+759+d10172d4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pyyaml-5.4.1-1.module_el8.5.0+759+d10172d4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-requests-2.25.0-2.module_el8.4.0+680+7b309a77', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-requests-2.25.0-2.module_el8.4.0+680+7b309a77', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-scipy-1.5.4-3.module_el8.4.0+680+7b309a77', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-scipy-1.5.4-3.module_el8.4.0+680+7b309a77', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-setuptools-50.3.2-4.module_el8.5.0+897+68c4c210', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-setuptools-50.3.2-4.module_el8.5.0+897+68c4c210', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-setuptools-wheel-50.3.2-4.module_el8.5.0+897+68c4c210', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-setuptools-wheel-50.3.2-4.module_el8.5.0+897+68c4c210', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-six-1.15.0-3.module_el8.4.0+680+7b309a77', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-six-1.15.0-3.module_el8.4.0+680+7b309a77', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-toml-0.10.1-5.module_el8.4.0+680+7b309a77', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-toml-0.10.1-5.module_el8.4.0+680+7b309a77', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-urllib3-1.25.10-4.module_el8.5.0+859+e98e3670', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-urllib3-1.25.10-4.module_el8.5.0+859+e98e3670', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-wheel-0.35.1-4.module_el8.5.0+897+68c4c210', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python39-wheel-0.35.1-4.module_el8.5.0+897+68c4c210', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python39-wheel-wheel-0.35.1-4.module_el8.5.0+897+68c4c210', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python39-wheel-wheel-0.35.1-4.module_el8.5.0+897+68c4c210', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
};

var flag = 0;
appstreams_found = 0;
foreach module (keys(appstreams)) {
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
    foreach package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && _release) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python39-PyMySQL / python39-cffi / python39-chardet / etc');
}
