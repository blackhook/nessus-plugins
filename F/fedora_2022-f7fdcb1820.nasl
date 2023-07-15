#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2022-f7fdcb1820
#

include('compat.inc');

if (description)
{
  script_id(169254);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/23");

  script_cve_id(
    "CVE-2021-23414",
    "CVE-2022-45149",
    "CVE-2022-45150",
    "CVE-2022-45151",
    "CVE-2022-45152"
  );
  script_xref(name:"FEDORA", value:"2022-f7fdcb1820");

  script_name(english:"Fedora 36 : moodle (2022-f7fdcb1820)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 36 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2022-f7fdcb1820 advisory.

  - This affects the package video.js before 7.14.3. The src attribute of track tag allows to bypass HTML
    escaping and execute arbitrary code. (CVE-2021-23414)

  - A vulnerability was found in Moodle which exists due to insufficient validation of the HTTP request origin
    in course redirect URL. A user's CSRF token was unnecessarily included in the URL when being redirected to
    a course they have just restored. A remote attacker can trick the victim to visit a specially crafted web
    page and perform arbitrary actions on behalf of the victim on the vulnerable website. This flaw allows an
    attacker to perform cross-site request forgery attacks. (CVE-2022-45149)

  - A reflected cross-site scripting vulnerability was discovered in Moodle. This flaw exists due to
    insufficient sanitization of user-supplied data in policy tool. An attacker can trick the victim to open a
    specially crafted link that executes an arbitrary HTML and script code in user's browser in context of
    vulnerable website. This vulnerability may allow an attacker to perform cross-site scripting (XSS) attacks
    to gain access potentially sensitive information and modification of web pages. (CVE-2022-45150)

  - The stored-XSS vulnerability was discovered in Moodle which exists due to insufficient sanitization of
    user-supplied data in several social user profile fields. An attacker could inject and execute arbitrary
    HTML and script code in user's browser in context of vulnerable website. (CVE-2022-45151)

  - A blind Server-Side Request Forgery (SSRF) vulnerability was found in Moodle. This flaw exists due to
    insufficient validation of user-supplied input in LTI provider library. The library does not utilise
    Moodle's inbuilt cURL helper, which resulted in a blind SSRF risk. An attacker can send a specially
    crafted HTTP request and trick the application to initiate requests to arbitrary systems. This
    vulnerability allows a remote attacker to perform SSRF attacks. (CVE-2022-45152)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2022-f7fdcb1820");
  script_set_attribute(attribute:"solution", value:
"Update the affected moodle package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23414");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-45152");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^36([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 36', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'moodle-3.11.11-1.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'moodle');
}
