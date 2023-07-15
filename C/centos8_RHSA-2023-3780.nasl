#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2023:3780. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177539);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/05");

  script_cve_id("CVE-2023-24329");
  script_xref(name:"RHSA", value:"2023:3780");

  script_name(english:"CentOS 8 : python27:2.7 (CESA-2023:3780)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
CESA-2023:3780 advisory.

  - An issue in the urllib.parse component of Python before 3.11.4 allows attackers to bypass blocklisting
    methods by supplying a URL that starts with blank characters. (CVE-2023-24329)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:3780");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24329");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-nose-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-psycopg2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-sqlalchemy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-Cython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-attrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-backports");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-backports-ssl_match_hostname");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-markupsafe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-mock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-nose");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-numpy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-numpy-f2py");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-setuptools-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-setuptools_scm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-six");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-sqlalchemy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-wheel-wheel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS 8-Stream');
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/python27');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python27:2.7');
if ('2.7' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module python27:' + module_ver);

var appstreams = {
    'python27:2.7': [
      {'reference':'babel-2.5.1-10.module_el8.5.0+772+8dae0bfd', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'babel-2.5.1-10.module_el8.5.0+772+8dae0bfd', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-nose-docs-1.3.7-31.module_el8.5.0+894+1c54b371', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-nose-docs-1.3.7-31.module_el8.5.0+894+1c54b371', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-psycopg2-doc-2.7.5-7.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-psycopg2-doc-2.7.5-7.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-sqlalchemy-doc-1.3.2-2.module_el8.3.0+562+e162826a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-sqlalchemy-doc-1.3.2-2.module_el8.3.0+562+e162826a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-attrs-17.4.0-10.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-attrs-17.4.0-10.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-babel-2.5.1-10.module_el8.5.0+772+8dae0bfd', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-babel-2.5.1-10.module_el8.5.0+772+8dae0bfd', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-backports-1.0-16.module_el8.4.0+642+1dc4fb01', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-backports-1.0-16.module_el8.4.0+642+1dc4fb01', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-backports-ssl_match_hostname-3.5.0.1-12.module_el8.4.0+642+1dc4fb01', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-backports-ssl_match_hostname-3.5.0.1-12.module_el8.4.0+642+1dc4fb01', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-bson-3.7.0-1.module_el8.5.0+743+cd2f5d28', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-bson-3.7.0-1.module_el8.5.0+743+cd2f5d28', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-chardet-3.0.4-10.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-chardet-3.0.4-10.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-coverage-4.5.1-4.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-coverage-4.5.1-4.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-Cython-0.28.1-7.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-Cython-0.28.1-7.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-dns-1.15.0-10.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-dns-1.15.0-10.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-docs-2.7.16-2.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-docs-2.7.16-2.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-docs-info-2.7.16-2.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-docs-info-2.7.16-2.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-docutils-0.14-12.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-docutils-0.14-12.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-funcsigs-1.0.2-13.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-funcsigs-1.0.2-13.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-idna-2.5-7.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-idna-2.5-7.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-ipaddress-1.0.18-6.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-ipaddress-1.0.18-6.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-jinja2-2.10-9.module_el8.5.0+743+cd2f5d28', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-jinja2-2.10-9.module_el8.5.0+743+cd2f5d28', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-lxml-4.2.3-6.module_el8.6.0+1079+8d338a31', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-lxml-4.2.3-6.module_el8.6.0+1079+8d338a31', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-markupsafe-0.23-19.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-markupsafe-0.23-19.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-mock-2.0.0-13.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-mock-2.0.0-13.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-nose-1.3.7-31.module_el8.5.0+894+1c54b371', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-nose-1.3.7-31.module_el8.5.0+894+1c54b371', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-numpy-1.14.2-16.module_el8.4.0+642+1dc4fb01', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-numpy-1.14.2-16.module_el8.4.0+642+1dc4fb01', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-numpy-doc-1.14.2-16.module_el8.4.0+642+1dc4fb01', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-numpy-doc-1.14.2-16.module_el8.4.0+642+1dc4fb01', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-numpy-f2py-1.14.2-16.module_el8.4.0+642+1dc4fb01', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-numpy-f2py-1.14.2-16.module_el8.4.0+642+1dc4fb01', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pip-9.0.3-19.module_el8.6.0+987+71f62bb6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pip-9.0.3-19.module_el8.6.0+987+71f62bb6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pip-wheel-9.0.3-19.module_el8.6.0+987+71f62bb6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pip-wheel-9.0.3-19.module_el8.6.0+987+71f62bb6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pluggy-0.6.0-8.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pluggy-0.6.0-8.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-2.7.5-7.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-2.7.5-7.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-debug-2.7.5-7.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-debug-2.7.5-7.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-tests-2.7.5-7.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-tests-2.7.5-7.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-py-1.5.3-6.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-py-1.5.3-6.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pygments-2.2.0-22.module_el8.5.0+763+a555e7f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pygments-2.2.0-22.module_el8.5.0+763+a555e7f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pymongo-3.7.0-1.module_el8.5.0+743+cd2f5d28', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pymongo-3.7.0-1.module_el8.5.0+743+cd2f5d28', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pymongo-gridfs-3.7.0-1.module_el8.5.0+743+cd2f5d28', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pymongo-gridfs-3.7.0-1.module_el8.5.0+743+cd2f5d28', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-PyMySQL-0.8.0-10.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-PyMySQL-0.8.0-10.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pysocks-1.6.8-6.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pysocks-1.6.8-6.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pytest-3.4.2-13.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pytest-3.4.2-13.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pytest-mock-1.9.0-4.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pytest-mock-1.9.0-4.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pytz-2017.2-12.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pytz-2017.2-12.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pyyaml-3.12-16.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pyyaml-3.12-16.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-requests-2.20.0-3.module_el8.2.0+381+9a5b3c3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-requests-2.20.0-3.module_el8.2.0+381+9a5b3c3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-rpm-macros-3-38.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-rpm-macros-3-38.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-scipy-1.0.0-21.module_el8.5.0+763+a555e7f1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-scipy-1.0.0-21.module_el8.5.0+763+a555e7f1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-setuptools-39.0.1-13.module_el8.4.0+642+1dc4fb01', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-setuptools-39.0.1-13.module_el8.4.0+642+1dc4fb01', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-setuptools-wheel-39.0.1-13.module_el8.4.0+642+1dc4fb01', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-setuptools-wheel-39.0.1-13.module_el8.4.0+642+1dc4fb01', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-setuptools_scm-1.15.7-6.module_el8.1.0+219+cf9e6ac9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-setuptools_scm-1.15.7-6.module_el8.1.0+219+cf9e6ac9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-six-1.11.0-6.module_el8.4.0+642+1dc4fb01', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-six-1.11.0-6.module_el8.4.0+642+1dc4fb01', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-sqlalchemy-1.3.2-2.module_el8.3.0+478+7570e00c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-sqlalchemy-1.3.2-2.module_el8.3.0+478+7570e00c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-urllib3-1.24.2-3.module_el8.4.0+642+1dc4fb01', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-urllib3-1.24.2-3.module_el8.4.0+642+1dc4fb01', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-wheel-0.31.1-3.module_el8.5.0+894+1c54b371', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python2-wheel-0.31.1-3.module_el8.5.0+894+1c54b371', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python2-wheel-wheel-0.31.1-3.module_el8.5.0+894+1c54b371', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python2-wheel-wheel-0.31.1-3.module_el8.5.0+894+1c54b371', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
};

var flag = 0;
appstreams_found = 0;
foreach module (keys(appstreams)) {
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
    foreach package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
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
