#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2022:8492.
##

include('compat.inc');

if (description)
{
  script_id(168134);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2022-42919");
  script_xref(name:"RLSA", value:"2022:8492");
  script_xref(name:"IAVA", value:"2023-A-0061-S");

  script_name(english:"Rocky Linux 8 : python39:3.9 (RLSA-2022:8492)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2022:8492 advisory.

  - Python 3.9.x before 3.9.16 and 3.10.x before 3.10.9 on Linux allows local privilege escalation in a non-
    default configuration. The Python multiprocessing library, when used with the forkserver start method on
    Linux, allows pickles to be deserialized from any user in the same machine local network namespace, which
    in many system configurations means any user on the same machine. Pickles can execute arbitrary code.
    Thus, this allows for local user privilege escalation to the user that any forkserver process is running
    as. Setting multiprocessing.util.abstract_sockets_supported to False is a workaround. The forkserver start
    method for multiprocessing is not the default start method. This issue is Linux specific because only
    Linux supports abstract namespace sockets. CPython before 3.9 does not make use of Linux abstract
    namespace sockets by default. Support for users manually specifying an abstract namespace socket was added
    as a bugfix in 3.7.8 and 3.8.3, but users would need to make specific uncommon API calls in order to do
    that in CPython before 3.9. (CVE-2022-42919)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2022:8492");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42919");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:PyYAML-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:numpy-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-cffi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-cryptography-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-lxml-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-psutil-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-psycopg2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-cffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-cffi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-cryptography-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-lxml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-mod_wsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-numpy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-numpy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-numpy-f2py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-pip-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-ply");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-psutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-psutil-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-psycopg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-psycopg2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-psycopg2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-psycopg2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-pycparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-pysocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-pyyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-pyyaml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-scipy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-scipy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-setuptools-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-six");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-toml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-wheel-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:scipy-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'numpy-debugsource-1.19.4-3.module+el8.5.0+673+10283621', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'numpy-debugsource-1.19.4-3.module+el8.5.0+673+10283621', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-cffi-debugsource-1.14.3-2.module+el8.4.0+574+843c4898', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-cffi-debugsource-1.14.3-2.module+el8.4.0+574+843c4898', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-cryptography-debugsource-3.3.1-2.module+el8.5.0+673+10283621', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-cryptography-debugsource-3.3.1-2.module+el8.5.0+673+10283621', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-lxml-debugsource-4.6.5-1.module+el8.6.0+795+de4edbcc', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-lxml-debugsource-4.6.5-1.module+el8.6.0+795+de4edbcc', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-psutil-debugsource-5.8.0-4.module+el8.5.0+673+10283621', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-psutil-debugsource-5.8.0-4.module+el8.5.0+673+10283621', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-psycopg2-debugsource-2.8.6-2.module+el8.6.0+795+de4edbcc', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-psycopg2-debugsource-2.8.6-2.module+el8.6.0+795+de4edbcc', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-cffi-1.14.3-2.module+el8.4.0+574+843c4898', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-cffi-1.14.3-2.module+el8.4.0+574+843c4898', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-cffi-debuginfo-1.14.3-2.module+el8.4.0+574+843c4898', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-cffi-debuginfo-1.14.3-2.module+el8.4.0+574+843c4898', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-chardet-3.0.4-19.module+el8.4.0+574+843c4898', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-cryptography-3.3.1-2.module+el8.5.0+673+10283621', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-cryptography-3.3.1-2.module+el8.5.0+673+10283621', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-cryptography-debuginfo-3.3.1-2.module+el8.5.0+673+10283621', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-cryptography-debuginfo-3.3.1-2.module+el8.5.0+673+10283621', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-idna-2.10-3.module+el8.4.0+574+843c4898', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-lxml-4.6.5-1.module+el8.6.0+795+de4edbcc', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-lxml-4.6.5-1.module+el8.6.0+795+de4edbcc', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-lxml-debuginfo-4.6.5-1.module+el8.6.0+795+de4edbcc', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-lxml-debuginfo-4.6.5-1.module+el8.6.0+795+de4edbcc', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-mod_wsgi-4.7.1-5.module+el8.7.0+1064+ad564229', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-mod_wsgi-4.7.1-5.module+el8.7.0+1064+ad564229', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-numpy-1.19.4-3.module+el8.5.0+673+10283621', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-numpy-1.19.4-3.module+el8.5.0+673+10283621', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-numpy-debuginfo-1.19.4-3.module+el8.5.0+673+10283621', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-numpy-debuginfo-1.19.4-3.module+el8.5.0+673+10283621', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-numpy-doc-1.19.4-3.module+el8.5.0+673+10283621', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-numpy-f2py-1.19.4-3.module+el8.5.0+673+10283621', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-numpy-f2py-1.19.4-3.module+el8.5.0+673+10283621', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-pip-20.2.4-7.module+el8.7.0+1064+ad564229', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-pip-wheel-20.2.4-7.module+el8.7.0+1064+ad564229', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-ply-3.11-10.module+el8.4.0+574+843c4898', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-psutil-5.8.0-4.module+el8.5.0+673+10283621', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-psutil-5.8.0-4.module+el8.5.0+673+10283621', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-psutil-debuginfo-5.8.0-4.module+el8.5.0+673+10283621', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-psutil-debuginfo-5.8.0-4.module+el8.5.0+673+10283621', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-psycopg2-2.8.6-2.module+el8.6.0+795+de4edbcc', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-psycopg2-2.8.6-2.module+el8.6.0+795+de4edbcc', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-psycopg2-debuginfo-2.8.6-2.module+el8.6.0+795+de4edbcc', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-psycopg2-debuginfo-2.8.6-2.module+el8.6.0+795+de4edbcc', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-psycopg2-doc-2.8.6-2.module+el8.6.0+795+de4edbcc', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-psycopg2-doc-2.8.6-2.module+el8.6.0+795+de4edbcc', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-psycopg2-tests-2.8.6-2.module+el8.6.0+795+de4edbcc', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-psycopg2-tests-2.8.6-2.module+el8.6.0+795+de4edbcc', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-pycparser-2.20-3.module+el8.4.0+574+843c4898', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-PyMySQL-0.10.1-2.module+el8.5.0+673+10283621', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-pysocks-1.7.1-4.module+el8.4.0+574+843c4898', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-pyyaml-5.4.1-1.module+el8.5.0+673+10283621', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-pyyaml-5.4.1-1.module+el8.5.0+673+10283621', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-pyyaml-debuginfo-5.4.1-1.module+el8.5.0+673+10283621', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-pyyaml-debuginfo-5.4.1-1.module+el8.5.0+673+10283621', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-requests-2.25.0-2.module+el8.4.0+574+843c4898', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-scipy-1.5.4-3.module+el8.5.0+673+10283621', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-scipy-1.5.4-3.module+el8.5.0+673+10283621', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-scipy-debuginfo-1.5.4-3.module+el8.5.0+673+10283621', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-scipy-debuginfo-1.5.4-3.module+el8.5.0+673+10283621', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-setuptools-50.3.2-4.module+el8.5.0+673+10283621', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-setuptools-wheel-50.3.2-4.module+el8.5.0+673+10283621', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-six-1.15.0-3.module+el8.4.0+574+843c4898', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-toml-0.10.1-5.module+el8.4.0+574+843c4898', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-urllib3-1.25.10-4.module+el8.5.0+673+10283621', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python39-wheel-0.35.1-4.module+el8.5.0+673+10283621', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python39-wheel-wheel-0.35.1-4.module+el8.5.0+673+10283621', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'PyYAML-debugsource-5.4.1-1.module+el8.5.0+673+10283621', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'PyYAML-debugsource-5.4.1-1.module+el8.5.0+673+10283621', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'scipy-debugsource-1.5.4-3.module+el8.5.0+673+10283621', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'scipy-debugsource-1.5.4-3.module+el8.5.0+673+10283621', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
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
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'PyYAML-debugsource / numpy-debugsource / python-cffi-debugsource / etc');
}
