#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-a53ab7c969
#

include('compat.inc');

if (description)
{
  script_id(174911);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/29");

  script_cve_id(
    "CVE-2022-28346",
    "CVE-2022-28347",
    "CVE-2022-34265",
    "CVE-2022-36359",
    "CVE-2022-41323",
    "CVE-2023-23969",
    "CVE-2023-24580"
  );
  script_xref(name:"FEDORA", value:"2023-a53ab7c969");

  script_name(english:"Fedora 38 : python-django (2023-a53ab7c969)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 38 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2023-a53ab7c969 advisory.

  - An issue was discovered in Django 2.2 before 2.2.28, 3.2 before 3.2.13, and 4.0 before 4.0.4.
    QuerySet.annotate(), aggregate(), and extra() methods are subject to SQL injection in column aliases via a
    crafted dictionary (with dictionary expansion) as the passed **kwargs. (CVE-2022-28346)

  - A SQL injection issue was discovered in QuerySet.explain() in Django 2.2 before 2.2.28, 3.2 before 3.2.13,
    and 4.0 before 4.0.4. This occurs by passing a crafted dictionary (with dictionary expansion) as the
    **options argument, and placing the injection payload in an option name. (CVE-2022-28347)

  - An issue was discovered in Django 3.2 before 3.2.14 and 4.0 before 4.0.6. The Trunc() and Extract()
    database functions are subject to SQL injection if untrusted data is used as a kind/lookup_name value.
    Applications that constrain the lookup name and kind choice to a known safe list are unaffected.
    (CVE-2022-34265)

  - In Django 3.2 before 3.2.16, 4.0 before 4.0.8, and 4.1 before 4.1.2, internationalized URLs were subject
    to a potential denial of service attack via the locale parameter, which is treated as a regular
    expression. (CVE-2022-41323)

  - In Django 3.2 before 3.2.17, 4.0 before 4.0.9, and 4.1 before 4.1.6, the parsed values of Accept-Language
    headers are cached in order to avoid repetitive parsing. This leads to a potential denial-of-service
    vector via excessive memory usage if the raw value of Accept-Language headers is very large.
    (CVE-2023-23969)

  - An issue was discovered in the Multipart Request Parser in Django 3.2 before 3.2.18, 4.0 before 4.0.10,
    and 4.1 before 4.1.7. Passing certain inputs (e.g., an excessive number of parts) to multipart forms could
    result in too many open files or memory exhaustion, and provided a potential vector for a denial-of-
    service attack. (CVE-2023-24580)

  - An issue was discovered in the HTTP FileResponse class in Django 3.2 before 3.2.15 and 4.0 before 4.0.7.
    An application is vulnerable to a reflected file download (RFD) attack that sets the Content-Disposition
    header of a FileResponse when the filename is derived from user-supplied input. (CVE-2022-36359)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-a53ab7c969");
  script_set_attribute(attribute:"solution", value:
"Update the affected python-django package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34265");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:python-django");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^38([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 38', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'python-django-4.0.10-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-django');
}
