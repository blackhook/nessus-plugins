#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2023:2764.
##

include('compat.inc');

if (description)
{
  script_id(176154);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/20");

  script_cve_id("CVE-2020-10735", "CVE-2021-28861", "CVE-2022-45061");
  script_xref(name:"ALSA", value:"2023:2764");
  script_xref(name:"IAVA", value:"2022-A-0467-S");
  script_xref(name:"IAVA", value:"2023-A-0061-S");

  script_name(english:"AlmaLinux 8 : python39:3.9 and python39-devel:3.9 (ALSA-2023:2764)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2023:2764 advisory.

  - A flaw was found in python. In algorithms with quadratic time complexity using non-binary bases, when
    using int(text), a system could take 50ms to parse an int string with 100,000 digits and 5s for
    1,000,000 digits (float, decimal, int.from_bytes(), and int() for binary bases 2, 4, 8, 16, and 32 are not
    affected). The highest threat from this vulnerability is to system availability. (CVE-2020-10735)

  - ** DISPUTED ** Python 3.x through 3.10 has an open redirection vulnerability in lib/http/server.py due to
    no protection against multiple (/) at the beginning of URI path which may leads to information disclosure.
    NOTE: this is disputed by a third party because the http.server.html documentation page states Warning:
    http.server is not recommended for production. It only implements basic security checks. (CVE-2021-28861)

  - An issue was discovered in Python before 3.11.1. An unnecessary quadratic algorithm exists in one path
    when processing some inputs to the IDNA (RFC 3490) decoder, such that a crafted, unreasonably long name
    being presented to the decoder could lead to a CPU denial of service. Hostnames are often supplied by
    remote servers that could be controlled by a malicious actor; in such a scenario, they could trigger
    excessive CPU consumption on the client attempting to make use of an attacker-supplied supposed hostname.
    For example, the attack payload could be placed in the Location header of an HTTP response with status
    code 302. A fix is planned in 3.11.1, 3.10.9, 3.9.16, 3.8.16, and 3.7.16. (CVE-2022-45061)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2023-2764.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28861");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(400, 601, 704);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-Cython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-attrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-cffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-iniconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-mod_wsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-more-itertools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-numpy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-numpy-f2py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-packaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-pip-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-pluggy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-ply");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-psutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-psycopg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-psycopg2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-psycopg2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-pybind11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-pybind11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-pycparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-pyparsing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-pysocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-pytest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-pyyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-scipy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-setuptools-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-six");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-toml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-wcwidth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python39-wheel-wheel");
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
  script_set_attribute(attribute:"stig_severity", value:"I");
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

var appstreams = {
    'python39-devel:3.9': [
      {'reference':'python39-3.9.16-1.module_el8.8.0+3483+a028a3dd', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-3.9.16-1.module_el8.8.0+3483+a028a3dd', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cffi-1.14.3-2.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cffi-1.14.3-2.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cryptography-3.3.1-2.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cryptography-3.3.1-2.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-Cython-0.29.21-5.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-Cython-0.29.21-5.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-debug-3.9.16-1.module_el8.8.0+3483+a028a3dd', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-debug-3.9.16-1.module_el8.8.0+3483+a028a3dd', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-devel-3.9.16-1.module_el8.8.0+3483+a028a3dd', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-devel-3.9.16-1.module_el8.8.0+3483+a028a3dd', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-idle-3.9.16-1.module_el8.8.0+3483+a028a3dd', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-idle-3.9.16-1.module_el8.8.0+3483+a028a3dd', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-libs-3.9.16-1.module_el8.8.0+3483+a028a3dd', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-libs-3.9.16-1.module_el8.8.0+3483+a028a3dd', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-lxml-4.6.5-1.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-lxml-4.6.5-1.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-mod_wsgi-4.7.1-5.module_el8.7.0+3344+df07b58a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-mod_wsgi-4.7.1-5.module_el8.7.0+3344+df07b58a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-1.19.4-3.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-1.19.4-3.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-f2py-1.19.4-3.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-f2py-1.19.4-3.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psutil-5.8.0-4.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psutil-5.8.0-4.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-2.8.6-2.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-2.8.6-2.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-doc-2.8.6-2.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-doc-2.8.6-2.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-tests-2.8.6-2.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-tests-2.8.6-2.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pybind11-2.7.1-1.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pybind11-2.7.1-1.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pybind11-devel-2.7.1-1.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pybind11-devel-2.7.1-1.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pyyaml-5.4.1-1.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pyyaml-5.4.1-1.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-scipy-1.5.4-3.module_el8.6.0+2780+a40f65e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-scipy-1.5.4-3.module_el8.6.0+2780+a40f65e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-test-3.9.16-1.module_el8.8.0+3483+a028a3dd', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-test-3.9.16-1.module_el8.8.0+3483+a028a3dd', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-tkinter-3.9.16-1.module_el8.8.0+3483+a028a3dd', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-tkinter-3.9.16-1.module_el8.8.0+3483+a028a3dd', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ],
    'python39:3.9': [
      {'reference':'python39-attrs-20.3.0-2.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-chardet-3.0.4-19.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-idna-2.10-3.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-iniconfig-1.1.1-2.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-more-itertools-8.5.0-2.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-doc-1.19.4-3.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-packaging-20.4-4.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pip-20.2.4-7.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pip-wheel-20.2.4-7.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pluggy-0.13.1-3.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-ply-3.11-10.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-py-1.10.0-1.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pycparser-2.20-3.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-PyMySQL-0.10.1-2.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pyparsing-2.4.7-5.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pysocks-1.7.1-4.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pytest-6.0.2-2.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-requests-2.25.0-2.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-rpm-macros-3.9.16-1.module_el8.8.0+3483+a028a3dd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-setuptools-50.3.2-4.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-setuptools-wheel-50.3.2-4.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-six-1.15.0-3.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-toml-0.10.1-5.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-urllib3-1.25.10-4.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-wcwidth-0.2.5-3.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-wheel-0.35.1-4.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python39-wheel-wheel-0.35.1-4.module_el8.6.0+2780+a40f65e1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python39-devel:3.9 / python39:3.9');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python39 / python39-Cython / python39-PyMySQL / python39-attrs / etc');
}
