#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2021:1761. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149749);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/02");

  script_cve_id(
    "CVE-2020-26116",
    "CVE-2020-26137",
    "CVE-2020-27783",
    "CVE-2021-3177"
  );
  script_xref(name:"RHSA", value:"2021:1761");

  script_name(english:"CentOS 8 : python27:2.7 (CESA-2021:1761)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2021:1761 advisory.

  - python: CRLF injection via HTTP request method in httplib/http.client (CVE-2020-26116)

  - python-urllib3: CRLF injection via HTTP request method (CVE-2020-26137)

  - python-lxml: mXSS due to the use of improper parser (CVE-2020-27783)

  - python: Stack-based buffer overflow in PyCArg_repr in _ctypes/callproc.c (CVE-2021-3177)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:1761");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3177");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-nose-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-psycopg2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-sqlalchemy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-Cython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-attrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-coverage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-docs-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-docutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-funcsigs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-ipaddress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-markupsafe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-mock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-nose");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-pip-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-pluggy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-psycopg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-psycopg2-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-psycopg2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-pygments");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-pymongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-pymongo-gridfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-pysocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-pytest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-pytest-mock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-pytz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-pyyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-scipy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-setuptools_scm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-sqlalchemy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-virtualenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-wheel-wheel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >< release) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS Stream ' + os_ver);
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

pkgs = [
    {'reference':'babel-2.5.1-9.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'babel-2.5.1-9.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-nose-docs-1.3.7-30.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-nose-docs-1.3.7-30.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-psycopg2-doc-2.7.5-7.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-psycopg2-doc-2.7.5-7.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-sqlalchemy-doc-1.3.2-2.module_el8.3.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-sqlalchemy-doc-1.3.2-2.module_el8.3.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-attrs-17.4.0-10.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-attrs-17.4.0-10.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-babel-2.5.1-9.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-babel-2.5.1-9.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-bson-3.6.1-11.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-bson-3.6.1-11.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-chardet-3.0.4-10.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-chardet-3.0.4-10.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-coverage-4.5.1-4.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-coverage-4.5.1-4.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-Cython-0.28.1-7.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-Cython-0.28.1-7.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-dns-1.15.0-10.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-dns-1.15.0-10.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-docs-2.7.16-2.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-docs-2.7.16-2.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-docs-info-2.7.16-2.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-docs-info-2.7.16-2.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-docutils-0.14-12.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-docutils-0.14-12.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-funcsigs-1.0.2-13.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-funcsigs-1.0.2-13.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-idna-2.5-7.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-idna-2.5-7.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-ipaddress-1.0.18-6.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-ipaddress-1.0.18-6.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-jinja2-2.10-8.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-jinja2-2.10-8.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-markupsafe-0.23-19.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-markupsafe-0.23-19.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-mock-2.0.0-13.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-mock-2.0.0-13.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-nose-1.3.7-30.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-nose-1.3.7-30.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pip-9.0.3-18.module_el8.3.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pip-9.0.3-18.module_el8.3.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pip-wheel-9.0.3-18.module_el8.3.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pip-wheel-9.0.3-18.module_el8.3.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pluggy-0.6.0-8.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pluggy-0.6.0-8.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-psycopg2-2.7.5-7.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-psycopg2-2.7.5-7.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-psycopg2-debug-2.7.5-7.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-psycopg2-debug-2.7.5-7.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-psycopg2-tests-2.7.5-7.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-psycopg2-tests-2.7.5-7.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-py-1.5.3-6.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-py-1.5.3-6.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pygments-2.2.0-20.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pygments-2.2.0-20.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pymongo-3.6.1-11.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pymongo-3.6.1-11.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pymongo-gridfs-3.6.1-11.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pymongo-gridfs-3.6.1-11.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-PyMySQL-0.8.0-10.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-PyMySQL-0.8.0-10.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pysocks-1.6.8-6.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pysocks-1.6.8-6.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pytest-3.4.2-13.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pytest-3.4.2-13.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pytest-mock-1.9.0-4.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pytest-mock-1.9.0-4.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pytz-2017.2-12.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pytz-2017.2-12.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pyyaml-3.12-16.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pyyaml-3.12-16.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-requests-2.20.0-3.module_el8.2.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-requests-2.20.0-3.module_el8.2.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-rpm-macros-3-38.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-rpm-macros-3-38.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-scipy-1.0.0-20.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-scipy-1.0.0-20.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-setuptools_scm-1.15.7-6.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-setuptools_scm-1.15.7-6.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-sqlalchemy-1.3.2-2.module_el8.3.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-sqlalchemy-1.3.2-2.module_el8.3.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-virtualenv-15.1.0-19.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-virtualenv-15.1.0-19.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-wheel-0.31.1-2.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python2-wheel-0.31.1-2.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python2-wheel-wheel-0.31.1-2.module_el8.1.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python2-wheel-wheel-0.31.1-2.module_el8.1.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'CentOS-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'babel / python-nose-docs / python-psycopg2-doc / python-sqlalchemy-doc / etc');
}
