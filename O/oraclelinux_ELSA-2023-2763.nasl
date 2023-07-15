#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-2763.
##

include('compat.inc');

if (description)
{
  script_id(176300);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id("CVE-2020-10735", "CVE-2021-28861", "CVE-2022-45061");
  script_xref(name:"IAVA", value:"2022-A-0467-S");
  script_xref(name:"IAVA", value:"2023-A-0061-S");

  script_name(english:"Oracle Linux 8 : python38:3.8 / and / python38-devel:3.8 (ELSA-2023-2763)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2023-2763 advisory.

  - An issue was discovered in Python before 3.11.1. An unnecessary quadratic algorithm exists in one path
    when processing some inputs to the IDNA (RFC 3490) decoder, such that a crafted, unreasonably long name
    being presented to the decoder could lead to a CPU denial of service. Hostnames are often supplied by
    remote servers that could be controlled by a malicious actor; in such a scenario, they could trigger
    excessive CPU consumption on the client attempting to make use of an attacker-supplied supposed hostname.
    For example, the attack payload could be placed in the Location header of an HTTP response with status
    code 302. A fix is planned in 3.11.1, 3.10.9, 3.9.16, 3.8.16, and 3.7.16. (CVE-2022-45061)

  - A flaw was found in python. In algorithms with quadratic time complexity using non-binary bases, when
    using int(text), a system could take 50ms to parse an int string with 100,000 digits and 5s for
    1,000,000 digits (float, decimal, int.from_bytes(), and int() for binary bases 2, 4, 8, 16, and 32 are not
    affected). The highest threat from this vulnerability is to system availability. (CVE-2020-10735)

  - ** DISPUTED ** Python 3.x through 3.10 has an open redirection vulnerability in lib/http/server.py due to
    no protection against multiple (/) at the beginning of URI path which may leads to information disclosure.
    NOTE: this is disputed by a third party because the http.server.html documentation page states Warning:
    http.server is not recommended for production. It only implements basic security checks. (CVE-2021-28861)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-2763.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28861");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-Cython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-asn1crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-atomicwrites");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-attrs");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-more-itertools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-numpy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-numpy-f2py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-packaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-pip-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-pluggy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-ply");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-psutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-psycopg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-psycopg2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-psycopg2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-pycparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-pyparsing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-pysocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-pytest");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-wcwidth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python38-wheel-wheel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/python38');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python38:3.8');
if ('3.8' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module python38:' + module_ver);

var appstreams = {
    'python38:3.8': [
      {'reference':'python38-PyMySQL-0.10.1-1.module+el8.4.0+20068+32a535e2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-asn1crypto-1.2.0-3.module+el8.4.0+20068+32a535e2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-atomicwrites-1.3.0-8.module+el8.2.0+5579+085cd3bd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-attrs-19.3.0-3.module+el8.2.0+5579+085cd3bd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-babel-2.7.0-11.module+el8.5.0+20371+4f24d723', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-chardet-3.0.4-19.module+el8.4.0+20068+32a535e2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-idna-2.8-6.module+el8.4.0+20068+32a535e2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-jinja2-2.11.3-1.module+el8.7.0+20792+22659047', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-more-itertools-7.2.0-5.module+el8.2.0+5579+085cd3bd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-numpy-doc-1.17.3-6.module+el8.5.0+20371+4f24d723', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-packaging-19.2-3.module+el8.2.0+5579+085cd3bd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pip-19.3.1-6.module+el8.7.0+20792+22659047', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pip-wheel-19.3.1-6.module+el8.7.0+20792+22659047', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pluggy-0.13.0-3.module+el8.2.0+5579+085cd3bd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-ply-3.11-10.module+el8.4.0+20068+32a535e2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-py-1.8.0-8.module+el8.2.0+5579+085cd3bd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pycparser-2.19-3.module+el8.4.0+20068+32a535e2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pyparsing-2.4.5-3.module+el8.2.0+5579+085cd3bd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pysocks-1.7.1-4.module+el8.4.0+20068+32a535e2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pytest-4.6.6-3.module+el8.2.0+5579+085cd3bd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pytz-2019.3-3.module+el8.4.0+20068+32a535e2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-requests-2.22.0-9.module+el8.4.0+20068+32a535e2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-rpm-macros-3.8.16-1.module+el8.8.0+21001+646f3fba', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-setuptools-41.6.0-5.module+el8.5.0+20371+4f24d723', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-setuptools-wheel-41.6.0-5.module+el8.5.0+20371+4f24d723', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-six-1.12.0-10.module+el8.4.0+20068+32a535e2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-urllib3-1.25.7-5.module+el8.5.0+20371+4f24d723', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-wcwidth-0.1.7-16.module+el8.2.0+5579+085cd3bd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-wheel-0.33.6-6.module+el8.5.0+20371+4f24d723', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-wheel-wheel-0.33.6-6.module+el8.5.0+20371+4f24d723', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-3.8.16-1.module+el8.8.0+21001+646f3fba', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-Cython-0.29.14-4.module+el8.4.0+20068+32a535e2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-cffi-1.13.2-3.module+el8.4.0+20068+32a535e2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-cryptography-2.8-3.module+el8.4.0+20068+32a535e2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-debug-3.8.16-1.module+el8.8.0+21001+646f3fba', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-devel-3.8.16-1.module+el8.8.0+21001+646f3fba', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-idle-3.8.16-1.module+el8.8.0+21001+646f3fba', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-libs-3.8.16-1.module+el8.8.0+21001+646f3fba', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-lxml-4.4.1-7.module+el8.6.0+20556+9910889d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-markupsafe-1.1.1-6.module+el8.4.0+20068+32a535e2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-mod_wsgi-4.6.8-4.module+el8.7.0+20869+e1465161', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-numpy-1.17.3-6.module+el8.5.0+20371+4f24d723', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-numpy-f2py-1.17.3-6.module+el8.5.0+20371+4f24d723', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-psutil-5.6.4-4.module+el8.5.0+20371+4f24d723', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-psycopg2-2.8.4-4.module+el8.4.0+20068+32a535e2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-psycopg2-doc-2.8.4-4.module+el8.4.0+20068+32a535e2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-psycopg2-tests-2.8.4-4.module+el8.4.0+20068+32a535e2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pyyaml-5.4.1-1.module+el8.5.0+20371+4f24d723', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-scipy-1.3.1-4.module+el8.4.0+20068+32a535e2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-test-3.8.16-1.module+el8.8.0+21001+646f3fba', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-tkinter-3.8.16-1.module+el8.8.0+21001+646f3fba', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-3.8.16-1.module+el8.8.0+21001+646f3fba', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-Cython-0.29.14-4.module+el8.4.0+20068+32a535e2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-cffi-1.13.2-3.module+el8.4.0+20068+32a535e2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-cryptography-2.8-3.module+el8.4.0+20068+32a535e2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-debug-3.8.16-1.module+el8.8.0+21001+646f3fba', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-devel-3.8.16-1.module+el8.8.0+21001+646f3fba', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-idle-3.8.16-1.module+el8.8.0+21001+646f3fba', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-libs-3.8.16-1.module+el8.8.0+21001+646f3fba', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-lxml-4.4.1-7.module+el8.6.0+20556+9910889d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-markupsafe-1.1.1-6.module+el8.4.0+20068+32a535e2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-mod_wsgi-4.6.8-4.module+el8.7.0+20869+e1465161', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-numpy-1.17.3-6.module+el8.5.0+20371+4f24d723', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-numpy-f2py-1.17.3-6.module+el8.5.0+20371+4f24d723', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-psutil-5.6.4-4.module+el8.5.0+20371+4f24d723', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-psycopg2-2.8.4-4.module+el8.4.0+20068+32a535e2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-psycopg2-doc-2.8.4-4.module+el8.4.0+20068+32a535e2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-psycopg2-tests-2.8.4-4.module+el8.4.0+20068+32a535e2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pyyaml-5.4.1-1.module+el8.5.0+20371+4f24d723', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-scipy-1.3.1-4.module+el8.4.0+20068+32a535e2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-test-3.8.16-1.module+el8.8.0+21001+646f3fba', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-tkinter-3.8.16-1.module+el8.8.0+21001+646f3fba', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
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
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python38:3.8');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python38 / python38-Cython / python38-PyMySQL / etc');
}
