#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-2860.
##

include('compat.inc');

if (description)
{
  script_id(176313);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id("CVE-2022-45061");
  script_xref(name:"IAVA", value:"2022-A-0467-S");
  script_xref(name:"IAVA", value:"2023-A-0061-S");

  script_name(english:"Oracle Linux 8 : python27:2.7 (ELSA-2023-2860)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2023-2860 advisory.

  - An issue was discovered in Python before 3.11.1. An unnecessary quadratic algorithm exists in one path
    when processing some inputs to the IDNA (RFC 3490) decoder, such that a crafted, unreasonably long name
    being presented to the decoder could lead to a CPU denial of service. Hostnames are often supplied by
    remote servers that could be controlled by a malicious actor; in such a scenario, they could trigger
    excessive CPU consumption on the client attempting to make use of an attacker-supplied supposed hostname.
    For example, the attack payload could be placed in the Location header of an HTTP response with status
    code 302. A fix is planned in 3.11.1, 3.10.9, 3.9.16, 3.8.16, and 3.7.16. (CVE-2022-45061)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-2860.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-45061");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-nose-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-psycopg2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-sqlalchemy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-Cython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-attrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-backports");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-backports-ssl_match_hostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-coverage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-docs-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-docutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-funcsigs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-ipaddress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-markupsafe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-mock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-nose");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-numpy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-numpy-f2py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-pip-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-pluggy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-psycopg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-psycopg2-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-psycopg2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-pygments");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-pymongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-pymongo-gridfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-pysocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-pytest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-pytest-mock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-pytz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-pyyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-scipy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-setuptools-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-setuptools_scm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-six");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-sqlalchemy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-virtualenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-wheel-wheel");
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

var module_ver = get_kb_item('Host/RedHat/appstream/python27');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python27:2.7');
if ('2.7' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module python27:' + module_ver);

var appstreams = {
    'python27:2.7': [
      {'reference':'babel-2.5.1-10.module+el8.5.0+20361+8a9d3d27', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-nose-docs-1.3.7-31.module+el8.5.0+20361+8a9d3d27', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-sqlalchemy-doc-1.3.2-2.module+el8.3.0+7833+4aaf98ce', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-PyMySQL-0.8.0-10.module+el8.3.0+7833+4aaf98ce', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-attrs-17.4.0-10.module+el8.3.0+7833+4aaf98ce', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-babel-2.5.1-10.module+el8.5.0+20361+8a9d3d27', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-backports-ssl_match_hostname-3.5.0.1-12.module+el8.4.0+20050+79c7b4ee', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-chardet-3.0.4-10.module+el8.3.0+7833+4aaf98ce', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-dns-1.15.0-10.module+el8.3.0+7833+4aaf98ce', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-docs-2.7.16-2.module+el8.3.0+7833+4aaf98ce', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-docs-info-2.7.16-2.module+el8.3.0+7833+4aaf98ce', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-docutils-0.14-12.module+el8.3.0+7833+4aaf98ce', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-funcsigs-1.0.2-13.module+el8.3.0+7833+4aaf98ce', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-idna-2.5-7.module+el8.3.0+7833+4aaf98ce', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-ipaddress-1.0.18-6.module+el8.3.0+7833+4aaf98ce', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-jinja2-2.10-9.module+el8.5.0+20361+8a9d3d27', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-mock-2.0.0-13.module+el8.3.0+7833+4aaf98ce', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-nose-1.3.7-31.module+el8.5.0+20361+8a9d3d27', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-numpy-doc-1.14.2-16.module+el8.4.0+20050+79c7b4ee', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python2-pip-9.0.3-19.module+el8.6.0+20550+a85dc526', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pip-wheel-9.0.3-19.module+el8.6.0+20550+a85dc526', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pluggy-0.6.0-8.module+el8.3.0+7833+4aaf98ce', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-py-1.5.3-6.module+el8.3.0+7833+4aaf98ce', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pygments-2.2.0-22.module+el8.5.0+20361+8a9d3d27', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pysocks-1.6.8-6.module+el8.3.0+7833+4aaf98ce', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pytest-3.4.2-13.module+el8.3.0+7833+4aaf98ce', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pytest-mock-1.9.0-4.module+el8.3.0+7833+4aaf98ce', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pytz-2017.2-12.module+el8.3.0+7833+4aaf98ce', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-requests-2.20.0-3.module+el8.3.0+7833+4aaf98ce', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-rpm-macros-3-38.module+el8.3.0+7833+4aaf98ce', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-setuptools-39.0.1-13.module+el8.4.0+20050+79c7b4ee', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-setuptools-wheel-39.0.1-13.module+el8.4.0+20050+79c7b4ee', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-setuptools_scm-1.15.7-6.module+el8.3.0+7833+4aaf98ce', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-six-1.11.0-6.module+el8.4.0+20050+79c7b4ee', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-urllib3-1.24.2-3.module+el8.4.0+20050+79c7b4ee', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-virtualenv-15.1.0-21.module+el8.5.0+20361+8a9d3d27', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-wheel-0.31.1-3.module+el8.5.0+20361+8a9d3d27', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python2-wheel-wheel-0.31.1-3.module+el8.5.0+20361+8a9d3d27', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python-psycopg2-doc-2.7.5-7.module+el8.3.0+7833+4aaf98ce', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-2.7.18-12.0.1.module+el8.8.0+20989+692249f4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-Cython-0.28.1-7.module+el8.3.0+7833+4aaf98ce', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-backports-1.0-16.module+el8.4.0+20050+79c7b4ee', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-bson-3.7.0-1.module+el8.5.0+20361+8a9d3d27', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-coverage-4.5.1-4.module+el8.3.0+7833+4aaf98ce', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-debug-2.7.18-12.0.1.module+el8.8.0+20989+692249f4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-devel-2.7.18-12.0.1.module+el8.8.0+20989+692249f4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-libs-2.7.18-12.0.1.module+el8.8.0+20989+692249f4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-lxml-4.2.3-6.module+el8.6.0+20550+a85dc526', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-markupsafe-0.23-19.module+el8.3.0+7833+4aaf98ce', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-numpy-1.14.2-16.module+el8.4.0+20050+79c7b4ee', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python2-numpy-f2py-1.14.2-16.module+el8.4.0+20050+79c7b4ee', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python2-psycopg2-2.7.5-7.module+el8.3.0+7833+4aaf98ce', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-debug-2.7.5-7.module+el8.3.0+7833+4aaf98ce', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-tests-2.7.5-7.module+el8.3.0+7833+4aaf98ce', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pymongo-3.7.0-1.module+el8.5.0+20361+8a9d3d27', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pymongo-gridfs-3.7.0-1.module+el8.5.0+20361+8a9d3d27', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pyyaml-3.12-16.module+el8.3.0+7833+4aaf98ce', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-scipy-1.0.0-21.module+el8.5.0+20361+8a9d3d27', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-sqlalchemy-1.3.2-2.module+el8.3.0+7833+4aaf98ce', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-test-2.7.18-12.0.1.module+el8.8.0+20989+692249f4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-tkinter-2.7.18-12.0.1.module+el8.8.0+20989+692249f4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-tools-2.7.18-12.0.1.module+el8.8.0+20989+692249f4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-psycopg2-doc-2.7.5-7.module+el8.3.0+7833+4aaf98ce', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-2.7.18-12.0.1.module+el8.8.0+20989+692249f4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-Cython-0.28.1-7.module+el8.3.0+7833+4aaf98ce', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-backports-1.0-16.module+el8.4.0+20050+79c7b4ee', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-bson-3.7.0-1.module+el8.5.0+20361+8a9d3d27', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-coverage-4.5.1-4.module+el8.3.0+7833+4aaf98ce', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-debug-2.7.18-12.0.1.module+el8.8.0+20989+692249f4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-devel-2.7.18-12.0.1.module+el8.8.0+20989+692249f4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-libs-2.7.18-12.0.1.module+el8.8.0+20989+692249f4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-lxml-4.2.3-6.module+el8.6.0+20550+a85dc526', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-markupsafe-0.23-19.module+el8.3.0+7833+4aaf98ce', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-numpy-1.14.2-16.module+el8.4.0+20050+79c7b4ee', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python2-numpy-f2py-1.14.2-16.module+el8.4.0+20050+79c7b4ee', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python2-psycopg2-2.7.5-7.module+el8.3.0+7833+4aaf98ce', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-debug-2.7.5-7.module+el8.3.0+7833+4aaf98ce', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-tests-2.7.5-7.module+el8.3.0+7833+4aaf98ce', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pymongo-3.7.0-1.module+el8.5.0+20361+8a9d3d27', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pymongo-gridfs-3.7.0-1.module+el8.5.0+20361+8a9d3d27', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pyyaml-3.12-16.module+el8.3.0+7833+4aaf98ce', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-scipy-1.0.0-21.module+el8.5.0+20361+8a9d3d27', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-sqlalchemy-1.3.2-2.module+el8.3.0+7833+4aaf98ce', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-test-2.7.18-12.0.1.module+el8.8.0+20989+692249f4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-tkinter-2.7.18-12.0.1.module+el8.8.0+20989+692249f4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-tools-2.7.18-12.0.1.module+el8.8.0+20989+692249f4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python27:2.7');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'babel / python-nose-docs / python-psycopg2-doc / etc');
}
