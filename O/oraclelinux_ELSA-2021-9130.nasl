##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-9130.
##

include('compat.inc');

if (description)
{
  script_id(147967);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/23");

  script_cve_id("CVE-2021-3177");

  script_name(english:"Oracle Linux 8 : python38 (ELSA-2021-9130)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2021-9130 advisory.

  - Python 3.x through 3.9.1 has a buffer overflow in PyCArg_repr in _ctypes/callproc.c, which may lead to
    remote code execution in certain Python applications that accept floating-point numbers as untrusted
    input, as demonstrated by a 1e300 argument to c_double.from_param. This occurs because sprintf is used
    unsafely. (CVE-2021-3177)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-9130.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3177");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-Cython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-asn1crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-cffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-markupsafe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-mod_wsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-numpy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-numpy-f2py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-pip-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-ply");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-psutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-psycopg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-psycopg2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-psycopg2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-pycparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-pysocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-pytz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-pyyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-scipy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-setuptools-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-six");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-wheel-wheel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

pkgs = [
    {'reference':'python38-3.8.3-3.0.1.module+el8.3.0+el8+9681+09f2c1ca', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-3.8.3-3.0.1.module+el8.3.0+el8+9681+09f2c1ca', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-asn1crypto-1.2.0-3.module+el8.3.0+7824+e0098946', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-babel-2.7.0-10.module+el8.3.0+7824+e0098946', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-cffi-1.13.2-3.module+el8.3.0+7824+e0098946', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-cffi-1.13.2-3.module+el8.3.0+7824+e0098946', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-chardet-3.0.4-19.module+el8.3.0+7824+e0098946', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-cryptography-2.8-3.module+el8.3.0+7824+e0098946', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-cryptography-2.8-3.module+el8.3.0+7824+e0098946', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-Cython-0.29.14-4.module+el8.3.0+7824+e0098946', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-Cython-0.29.14-4.module+el8.3.0+7824+e0098946', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-debug-3.8.3-3.0.1.module+el8.3.0+el8+9681+09f2c1ca', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-debug-3.8.3-3.0.1.module+el8.3.0+el8+9681+09f2c1ca', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-devel-3.8.3-3.0.1.module+el8.3.0+el8+9681+09f2c1ca', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-devel-3.8.3-3.0.1.module+el8.3.0+el8+9681+09f2c1ca', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-idle-3.8.3-3.0.1.module+el8.3.0+el8+9681+09f2c1ca', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-idle-3.8.3-3.0.1.module+el8.3.0+el8+9681+09f2c1ca', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-idna-2.8-6.module+el8.3.0+7824+e0098946', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-jinja2-2.10.3-4.module+el8.3.0+7824+e0098946', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-libs-3.8.3-3.0.1.module+el8.3.0+el8+9681+09f2c1ca', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-libs-3.8.3-3.0.1.module+el8.3.0+el8+9681+09f2c1ca', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-lxml-4.4.1-4.module+el8.3.0+7824+e0098946', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-lxml-4.4.1-4.module+el8.3.0+7824+e0098946', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-markupsafe-1.1.1-6.module+el8.3.0+7824+e0098946', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-markupsafe-1.1.1-6.module+el8.3.0+7824+e0098946', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-mod_wsgi-4.6.8-3.module+el8.3.0+7824+e0098946', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-mod_wsgi-4.6.8-3.module+el8.3.0+7824+e0098946', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-numpy-1.17.3-5.module+el8.3.0+7824+e0098946', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-numpy-1.17.3-5.module+el8.3.0+7824+e0098946', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-numpy-doc-1.17.3-5.module+el8.3.0+7824+e0098946', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-numpy-f2py-1.17.3-5.module+el8.3.0+7824+e0098946', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-numpy-f2py-1.17.3-5.module+el8.3.0+7824+e0098946', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-pip-19.3.1-1.module+el8.3.0+7824+e0098946', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-pip-wheel-19.3.1-1.module+el8.3.0+7824+e0098946', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-ply-3.11-8.module+el8.3.0+7824+e0098946', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-psutil-5.6.4-3.module+el8.3.0+7824+e0098946', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-psutil-5.6.4-3.module+el8.3.0+7824+e0098946', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-psycopg2-2.8.4-4.module+el8.3.0+7824+e0098946', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-psycopg2-2.8.4-4.module+el8.3.0+7824+e0098946', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-psycopg2-doc-2.8.4-4.module+el8.3.0+7824+e0098946', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-psycopg2-doc-2.8.4-4.module+el8.3.0+7824+e0098946', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-psycopg2-tests-2.8.4-4.module+el8.3.0+7824+e0098946', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-psycopg2-tests-2.8.4-4.module+el8.3.0+7824+e0098946', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-pycparser-2.19-3.module+el8.3.0+7824+e0098946', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-PyMySQL-0.9.3-3.module+el8.3.0+7824+e0098946', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-pysocks-1.7.1-4.module+el8.3.0+7824+e0098946', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-pytz-2019.3-3.module+el8.3.0+7824+e0098946', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-pyyaml-5.3.1-1.module+el8.3.0+7824+e0098946', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-pyyaml-5.3.1-1.module+el8.3.0+7824+e0098946', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-requests-2.22.0-9.module+el8.3.0+7824+e0098946', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-rpm-macros-3.8.3-3.0.1.module+el8.3.0+el8+9681+09f2c1ca', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-scipy-1.3.1-4.module+el8.3.0+7824+e0098946', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-scipy-1.3.1-4.module+el8.3.0+7824+e0098946', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-setuptools-41.6.0-4.module+el8.3.0+7824+e0098946', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-setuptools-wheel-41.6.0-4.module+el8.3.0+7824+e0098946', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-six-1.12.0-9.module+el8.3.0+7824+e0098946', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-test-3.8.3-3.0.1.module+el8.3.0+el8+9681+09f2c1ca', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-test-3.8.3-3.0.1.module+el8.3.0+el8+9681+09f2c1ca', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-tkinter-3.8.3-3.0.1.module+el8.3.0+el8+9681+09f2c1ca', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-tkinter-3.8.3-3.0.1.module+el8.3.0+el8+9681+09f2c1ca', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-urllib3-1.25.7-4.module+el8.3.0+7824+e0098946', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-wheel-0.33.6-5.module+el8.3.0+7824+e0098946', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python38-wheel-wheel-0.33.6-5.module+el8.3.0+7824+e0098946', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python38 / python38-Cython / python38-PyMySQL / etc');
}