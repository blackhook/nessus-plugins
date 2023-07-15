#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-9341.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160271);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2017-18342",
    "CVE-2020-10108",
    "CVE-2020-10109",
    "CVE-2020-27783",
    "CVE-2021-28658",
    "CVE-2021-28957",
    "CVE-2021-31542",
    "CVE-2021-33203",
    "CVE-2021-33571",
    "CVE-2021-43818",
    "CVE-2021-44420"
  );

  script_name(english:"Oracle Linux 8 : ol-automation-manager (ELSA-2022-9341)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2022-9341 advisory.

  - In Twisted Web through 19.10.0, there was an HTTP request splitting vulnerability. When presented with two
    content-length headers, it ignored the first header. When the second content-length value was set to zero,
    the request body was interpreted as a pipelined request. (CVE-2020-10108)

  - In Twisted Web through 19.10.0, there was an HTTP request splitting vulnerability. When presented with a
    content-length and a chunked encoding header, the content-length took precedence and the remainder of the
    request body was interpreted as a pipelined request. (CVE-2020-10109)

  - A XSS vulnerability was discovered in python-lxml's clean module. The module's parser didn't properly
    imitate browsers, which caused different behaviors between the sanitizer and the user's page. A remote
    attacker could exploit this flaw to run arbitrary HTML/JS code. (CVE-2020-27783)

  - In PyYAML before 5.1, the yaml.load() API could execute arbitrary code if used with untrusted data. The
    load() function has been deprecated in version 5.1 and the 'UnsafeLoader' has been introduced for backward
    compatibility with the function. (CVE-2017-18342)

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

  - In Django 2.2 before 2.2.21, 3.1 before 3.1.9, and 3.2 before 3.2.1, MultiPartParser, UploadedFile, and
    FieldFile allowed directory traversal via uploaded files with suitably crafted file names.
    (CVE-2021-31542)

  - In Django 2.2 before 2.2.20, 3.0 before 3.0.14, and 3.1 before 3.1.8, MultiPartParser allowed directory
    traversal via uploaded files with suitably crafted file names. Built-in upload handlers were not affected
    by this vulnerability. (CVE-2021-28658)

  - lxml is a library for processing XML and HTML in the Python language. Prior to version 4.6.5, the HTML
    Cleaner in lxml.html lets certain crafted script content pass through, as well as script content in SVG
    files embedded using data URIs. Users that employ the HTML cleaner in a security relevant context should
    upgrade to lxml 4.6.5 to receive a patch. There are no known workarounds available. (CVE-2021-43818)

  - An XSS vulnerability was discovered in python-lxml's clean module versions before 4.6.3. When disabling
    the safe_attrs_only and forms arguments, the Cleaner class does not remove the formaction attribute
    allowing for JS to bypass the sanitizer. A remote attacker could exploit this flaw to run arbitrary JS
    code on users who interact with incorrectly sanitized HTML. This issue is patched in lxml 4.6.3.
    (CVE-2021-28957)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-9341.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected ol-automation-manager, ol-automation-manager-cli and / or python3-olamkit packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44420");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-10109");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ol-automation-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ol-automation-manager-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-olamkit");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var pkgs = [
    {'reference':'ol-automation-manager-1.0.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ol-automation-manager-cli-1.0.2-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-olamkit-1.0.2-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
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
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release) {
    if (exists_check) {
        if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ol-automation-manager / ol-automation-manager-cli / python3-olamkit');
}
