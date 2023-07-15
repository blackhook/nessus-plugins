#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2021:2583. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151145);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id("CVE-2020-14343");
  script_xref(name:"RHSA", value:"2021:2583");
  script_xref(name:"IAVA", value:"2021-A-0463");

  script_name(english:"CentOS 8 : python38:3.8 and python38-devel:3.8 (CESA-2021:2583)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
CESA-2021:2583 advisory.

  - PyYAML: incomplete fix for CVE-2020-1747 (CVE-2020-14343)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:2583");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14343");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-Cython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-asn1crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-atomicwrites");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-attrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-cffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-markupsafe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-mod_wsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-more-itertools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-numpy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-numpy-f2py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-packaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-pip-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-pluggy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-ply");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-psutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-psycopg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-psycopg2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-psycopg2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-pycparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-pyparsing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-pysocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-pytest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-pytz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-pyyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-scipy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-setuptools-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-six");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-wcwidth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python38-wheel-wheel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if ('CentOS Stream' >< os_release) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS Stream ' + os_ver);
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/python38-devel');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python38-devel:3.8');
if ('3.8' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module python38-devel:' + module_ver);

var appstreams = {
    'python38-devel:3.8': [
      {'reference':'python38-3.8.6-3.module_el8.4.0+665+abc3a503', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-3.8.6-3.module_el8.4.0+665+abc3a503', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-asn1crypto-1.2.0-3.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-asn1crypto-1.2.0-3.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-atomicwrites-1.3.0-8.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-atomicwrites-1.3.0-8.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-attrs-19.3.0-3.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-attrs-19.3.0-3.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-babel-2.7.0-10.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-babel-2.7.0-10.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-cffi-1.13.2-3.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-cffi-1.13.2-3.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-chardet-3.0.4-19.module_el8.4.0+665+abc3a503', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-chardet-3.0.4-19.module_el8.4.0+665+abc3a503', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-cryptography-2.8-3.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-cryptography-2.8-3.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-Cython-0.29.14-4.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-Cython-0.29.14-4.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-debug-3.8.6-3.module_el8.4.0+665+abc3a503', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-debug-3.8.6-3.module_el8.4.0+665+abc3a503', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-devel-3.8.6-3.module_el8.4.0+665+abc3a503', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-devel-3.8.6-3.module_el8.4.0+665+abc3a503', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-idle-3.8.6-3.module_el8.4.0+665+abc3a503', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-idle-3.8.6-3.module_el8.4.0+665+abc3a503', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-idna-2.8-6.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-idna-2.8-6.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-jinja2-2.10.3-4.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-jinja2-2.10.3-4.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-libs-3.8.6-3.module_el8.4.0+665+abc3a503', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-libs-3.8.6-3.module_el8.4.0+665+abc3a503', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-lxml-4.4.1-5.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-lxml-4.4.1-5.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-markupsafe-1.1.1-6.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-markupsafe-1.1.1-6.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-mod_wsgi-4.6.8-3.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-mod_wsgi-4.6.8-3.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-more-itertools-7.2.0-5.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-more-itertools-7.2.0-5.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-numpy-1.17.3-5.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-numpy-1.17.3-5.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-numpy-doc-1.17.3-5.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-numpy-doc-1.17.3-5.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-numpy-f2py-1.17.3-5.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-numpy-f2py-1.17.3-5.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-packaging-19.2-3.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-packaging-19.2-3.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pip-19.3.1-1.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pip-19.3.1-1.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pip-wheel-19.3.1-1.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pip-wheel-19.3.1-1.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pluggy-0.13.0-3.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pluggy-0.13.0-3.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-ply-3.11-10.module_el8.4.0+665+abc3a503', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-ply-3.11-10.module_el8.4.0+665+abc3a503', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-psutil-5.6.4-3.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-psutil-5.6.4-3.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-psycopg2-2.8.4-4.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-psycopg2-2.8.4-4.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-psycopg2-doc-2.8.4-4.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-psycopg2-doc-2.8.4-4.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-psycopg2-tests-2.8.4-4.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-psycopg2-tests-2.8.4-4.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-py-1.8.0-8.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-py-1.8.0-8.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pycparser-2.19-3.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pycparser-2.19-3.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-PyMySQL-0.10.1-1.module_el8.4.0+677+b84873a2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-PyMySQL-0.10.1-1.module_el8.4.0+677+b84873a2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pyparsing-2.4.5-3.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pyparsing-2.4.5-3.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pysocks-1.7.1-4.module_el8.4.0+665+abc3a503', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pysocks-1.7.1-4.module_el8.4.0+665+abc3a503', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pytest-4.6.6-3.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pytest-4.6.6-3.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pytz-2019.3-3.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pytz-2019.3-3.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pyyaml-5.4.1-1.module_el8.4.0+850+38daddd7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-pyyaml-5.4.1-1.module_el8.4.0+850+38daddd7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-requests-2.22.0-9.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-requests-2.22.0-9.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-rpm-macros-3.8.6-3.module_el8.4.0+665+abc3a503', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-rpm-macros-3.8.6-3.module_el8.4.0+665+abc3a503', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-scipy-1.3.1-4.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-scipy-1.3.1-4.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-setuptools-41.6.0-4.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-setuptools-41.6.0-4.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-setuptools-wheel-41.6.0-4.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-setuptools-wheel-41.6.0-4.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-six-1.12.0-10.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-six-1.12.0-10.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-test-3.8.6-3.module_el8.4.0+665+abc3a503', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-test-3.8.6-3.module_el8.4.0+665+abc3a503', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-tkinter-3.8.6-3.module_el8.4.0+665+abc3a503', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-tkinter-3.8.6-3.module_el8.4.0+665+abc3a503', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-urllib3-1.25.7-4.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-urllib3-1.25.7-4.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-wcwidth-0.1.7-16.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-wcwidth-0.1.7-16.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-wheel-0.33.6-5.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-wheel-0.33.6-5.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-wheel-wheel-0.33.6-5.module_el8.4.0+647+0ba99ce8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python38-wheel-wheel-0.33.6-5.module_el8.4.0+647+0ba99ce8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python38-devel:3.8');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python38 / python38-Cython / python38-PyMySQL / python38-asn1crypto / etc');
}
