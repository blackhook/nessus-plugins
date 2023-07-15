##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-3888.
##

include('compat.inc');

if (description)
{
  script_id(141218);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id("CVE-2019-16935", "CVE-2020-8492");

  script_name(english:"Oracle Linux 7 : python3 (ELSA-2020-3888)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-3888 advisory.

  - The documentation XML-RPC server in Python through 2.7.16, 3.x through 3.6.9, and 3.7.x through 3.7.4 has
    XSS via the server_title field. This occurs in Lib/DocXMLRPCServer.py in Python 2.x, and in
    Lib/xmlrpc/server.py in Python 3.x. If set_server_title is called with untrusted input, arbitrary
    JavaScript can be delivered to clients that visit the http URL for this server. (CVE-2019-16935)

  - Python 2.7 through 2.7.17, 3.5 through 3.5.9, 3.6 through 3.6.10, 3.7 through 3.7.6, and 3.8 through 3.8.1
    allows an HTTP server to conduct Regular Expression Denial of Service (ReDoS) attacks against a client
    because of urllib.request.AbstractBasicAuthHandler catastrophic backtracking. (CVE-2020-8492)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://linux.oracle.com/errata/ELSA-2020-3888.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16935");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-tkinter");
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
    {'reference':'python3-3.6.8-17.0.1.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'python3-3.6.8-17.0.1.el7', 'cpu':'i686', 'release':'7'},
    {'reference':'python3-3.6.8-17.0.1.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'python3-debug-3.6.8-17.0.1.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'python3-debug-3.6.8-17.0.1.el7', 'cpu':'i686', 'release':'7'},
    {'reference':'python3-debug-3.6.8-17.0.1.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'python3-devel-3.6.8-17.0.1.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'python3-devel-3.6.8-17.0.1.el7', 'cpu':'i686', 'release':'7'},
    {'reference':'python3-devel-3.6.8-17.0.1.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'python3-idle-3.6.8-17.0.1.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'python3-idle-3.6.8-17.0.1.el7', 'cpu':'i686', 'release':'7'},
    {'reference':'python3-idle-3.6.8-17.0.1.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'python3-libs-3.6.8-17.0.1.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'python3-libs-3.6.8-17.0.1.el7', 'cpu':'i686', 'release':'7'},
    {'reference':'python3-libs-3.6.8-17.0.1.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'python3-test-3.6.8-17.0.1.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'python3-test-3.6.8-17.0.1.el7', 'cpu':'i686', 'release':'7'},
    {'reference':'python3-test-3.6.8-17.0.1.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'python3-tkinter-3.6.8-17.0.1.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'python3-tkinter-3.6.8-17.0.1.el7', 'cpu':'i686', 'release':'7'},
    {'reference':'python3-tkinter-3.6.8-17.0.1.el7', 'cpu':'x86_64', 'release':'7'}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python3 / python3-debug / python3-devel / etc');
}