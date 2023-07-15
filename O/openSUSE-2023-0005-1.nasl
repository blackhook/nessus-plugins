#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2023:0005-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(169481);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/04");

  script_cve_id(
    "CVE-2021-32052",
    "CVE-2021-33203",
    "CVE-2021-33571",
    "CVE-2021-44420",
    "CVE-2021-45115",
    "CVE-2021-45116",
    "CVE-2021-45452",
    "CVE-2022-22818",
    "CVE-2022-23833",
    "CVE-2022-28346",
    "CVE-2022-28347",
    "CVE-2022-36359",
    "CVE-2022-41323"
  );

  script_name(english:"openSUSE 15 Security Update : python-Django (openSUSE-SU-2023:0005-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has a package installed that is affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2023:0005-1 advisory.

  - In Django 2.2 before 2.2.22, 3.1 before 3.1.10, and 3.2 before 3.2.2 (with Python 3.9.5+), URLValidator
    does not prohibit newlines and tabs (unless the URLField form field is used). If an application uses
    values with newlines in an HTTP response, header injection can occur. Django itself is unaffected because
    HttpResponse prohibits newlines in HTTP headers. (CVE-2021-32052)

  - Django before 2.2.24, 3.x before 3.1.12, and 3.2.x before 3.2.4 has a potential directory traversal via
    django.contrib.admindocs. Staff members could use the TemplateDetailView view to check the existence of
    arbitrary files. Additionally, if (and only if) the default admindocs templates have been customized by
    application developers to also show file contents, then not only the existence but also the file contents
    would have been exposed. In other words, there is directory traversal outside of the template root
    directories. (CVE-2021-33203)

  - In Django 2.2 before 2.2.24, 3.x before 3.1.12, and 3.2 before 3.2.4, URLValidator, validate_ipv4_address,
    and validate_ipv46_address do not prohibit leading zero characters in octal literals. This may allow a
    bypass of access control that is based on IP addresses. (validate_ipv4_address and validate_ipv46_address
    are unaffected with Python 3.9.5+..) . (CVE-2021-33571)

  - In Django 2.2 before 2.2.25, 3.1 before 3.1.14, and 3.2 before 3.2.10, HTTP requests for URLs with
    trailing newlines could bypass upstream access control based on URL paths. (CVE-2021-44420)

  - An issue was discovered in Django 2.2 before 2.2.26, 3.2 before 3.2.11, and 4.0 before 4.0.1.
    UserAttributeSimilarityValidator incurred significant overhead in evaluating a submitted password that was
    artificially large in relation to the comparison values. In a situation where access to user registration
    was unrestricted, this provided a potential vector for a denial-of-service attack. (CVE-2021-45115)

  - An issue was discovered in Django 2.2 before 2.2.26, 3.2 before 3.2.11, and 4.0 before 4.0.1. Due to
    leveraging the Django Template Language's variable resolution logic, the dictsort template filter was
    potentially vulnerable to information disclosure, or an unintended method call, if passed a suitably
    crafted key. (CVE-2021-45116)

  - Storage.save in Django 2.2 before 2.2.26, 3.2 before 3.2.11, and 4.0 before 4.0.1 allows directory
    traversal if crafted filenames are directly passed to it. (CVE-2021-45452)

  - The {% debug %} template tag in Django 2.2 before 2.2.27, 3.2 before 3.2.12, and 4.0 before 4.0.2 does not
    properly encode the current context. This may lead to XSS. (CVE-2022-22818)

  - An issue was discovered in MultiPartParser in Django 2.2 before 2.2.27, 3.2 before 3.2.12, and 4.0 before
    4.0.2. Passing certain inputs to multipart forms could result in an infinite loop when parsing files.
    (CVE-2022-23833)

  - An issue was discovered in Django 2.2 before 2.2.28, 3.2 before 3.2.13, and 4.0 before 4.0.4.
    QuerySet.annotate(), aggregate(), and extra() methods are subject to SQL injection in column aliases via a
    crafted dictionary (with dictionary expansion) as the passed **kwargs. (CVE-2022-28346)

  - A SQL injection issue was discovered in QuerySet.explain() in Django 2.2 before 2.2.28, 3.2 before 3.2.13,
    and 4.0 before 4.0.4. This occurs by passing a crafted dictionary (with dictionary expansion) as the
    **options argument, and placing the injection payload in an option name. (CVE-2022-28347)

  - An issue was discovered in the HTTP FileResponse class in Django 3.2 before 3.2.15 and 4.0 before 4.0.7.
    An application is vulnerable to a reflected file download (RFD) attack that sets the Content-Disposition
    header of a FileResponse when the filename is derived from user-supplied input. (CVE-2022-36359)

  - In Django 3.2 before 3.2.16, 4.0 before 4.0.8, and 4.1 before 4.1.2, internationalized URLs were subject
    to a potential denial of service attack via the locale parameter, which is treated as a regular
    expression. (CVE-2022-41323)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185713");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193240");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194116");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198398");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203793");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/UHF5IZKTZ2T4T4QQYZMUFHW422X3WCU6/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ff6e271");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32052");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33203");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33571");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-44420");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-45115");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-45116");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-45452");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22818");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23833");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28346");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28347");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-36359");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-41323");
  script_set_attribute(attribute:"solution", value:
"Update the affected python3-Django package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28347");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-Django");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'python3-Django-2.2.28-bp153.2.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python3-Django');
}
