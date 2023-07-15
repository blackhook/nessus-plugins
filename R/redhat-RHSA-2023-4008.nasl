#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:4008. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178104);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2023-24329");
  script_xref(name:"RHSA", value:"2023:4008");
  script_xref(name:"IAVA", value:"2023-A-0118-S");
  script_xref(name:"IAVA", value:"2023-A-0283");

  script_name(english:"RHEL 8 : python38:3.8 and python38-devel:3.8 (RHSA-2023:4008)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2023:4008 advisory.

  - An issue in the urllib.parse component of Python before 3.11.4 allows attackers to bypass blocklisting
    methods by supplying a URL that starts with blank characters. (CVE-2023-24329)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-24329");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:4008");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24329");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-Cython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-asn1crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-cffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-markupsafe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-mod_wsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-numpy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-numpy-f2py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-pip-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-ply");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-psutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-psycopg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-psycopg2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-psycopg2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-pycparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-pysocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-pytz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-pyyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-scipy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-setuptools-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-six");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-wheel-wheel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '8.4')) audit(AUDIT_OS_NOT, 'Red Hat 8.4', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var appstreams = {
  'python38:3.8': [
    {
      'repo_relative_urls': [
        'content/aus/rhel8/8.4/x86_64/appstream/debug',
        'content/aus/rhel8/8.4/x86_64/appstream/os',
        'content/aus/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/aus/rhel8/8.4/x86_64/baseos/debug',
        'content/aus/rhel8/8.4/x86_64/baseos/os',
        'content/aus/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/appstream/debug',
        'content/e4s/rhel8/8.4/x86_64/appstream/os',
        'content/e4s/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/baseos/debug',
        'content/e4s/rhel8/8.4/x86_64/baseos/os',
        'content/e4s/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/highavailability/debug',
        'content/e4s/rhel8/8.4/x86_64/highavailability/os',
        'content/e4s/rhel8/8.4/x86_64/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/nfv/debug',
        'content/e4s/rhel8/8.4/x86_64/nfv/os',
        'content/e4s/rhel8/8.4/x86_64/nfv/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/sap-solutions/debug',
        'content/e4s/rhel8/8.4/x86_64/sap-solutions/os',
        'content/e4s/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/sap/debug',
        'content/e4s/rhel8/8.4/x86_64/sap/os',
        'content/e4s/rhel8/8.4/x86_64/sap/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/appstream/debug',
        'content/tus/rhel8/8.4/x86_64/appstream/os',
        'content/tus/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/baseos/debug',
        'content/tus/rhel8/8.4/x86_64/baseos/os',
        'content/tus/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/highavailability/debug',
        'content/tus/rhel8/8.4/x86_64/highavailability/os',
        'content/tus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/nfv/debug',
        'content/tus/rhel8/8.4/x86_64/nfv/os',
        'content/tus/rhel8/8.4/x86_64/nfv/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/rt/debug',
        'content/tus/rhel8/8.4/x86_64/rt/os',
        'content/tus/rhel8/8.4/x86_64/rt/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'python38-3.8.6-3.module+el8.4.0+19187+74687b24.2', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-3.8.6-3.module+el8.4.0+19187+74687b24.2', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-asn1crypto-1.2.0-3.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-babel-2.7.0-10.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-cffi-1.13.2-3.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-cffi-1.13.2-3.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-chardet-3.0.4-19.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-cryptography-2.8-3.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-cryptography-2.8-3.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-Cython-0.29.14-4.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-Cython-0.29.14-4.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-debug-3.8.6-3.module+el8.4.0+19187+74687b24.2', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-debug-3.8.6-3.module+el8.4.0+19187+74687b24.2', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-devel-3.8.6-3.module+el8.4.0+19187+74687b24.2', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-devel-3.8.6-3.module+el8.4.0+19187+74687b24.2', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-idle-3.8.6-3.module+el8.4.0+19187+74687b24.2', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-idle-3.8.6-3.module+el8.4.0+19187+74687b24.2', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-idna-2.8-6.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-jinja2-2.10.3-4.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-libs-3.8.6-3.module+el8.4.0+19187+74687b24.2', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-libs-3.8.6-3.module+el8.4.0+19187+74687b24.2', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-lxml-4.4.1-5.module+el8.4.0+9001+fc421f6c', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-lxml-4.4.1-5.module+el8.4.0+9001+fc421f6c', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-markupsafe-1.1.1-6.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-markupsafe-1.1.1-6.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-mod_wsgi-4.6.8-3.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-mod_wsgi-4.6.8-3.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-numpy-1.17.3-5.module+el8.4.0+15041+cb41100f.1', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-numpy-1.17.3-5.module+el8.4.0+15041+cb41100f.1', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-numpy-doc-1.17.3-5.module+el8.4.0+15041+cb41100f.1', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-numpy-f2py-1.17.3-5.module+el8.4.0+15041+cb41100f.1', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-numpy-f2py-1.17.3-5.module+el8.4.0+15041+cb41100f.1', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-pip-19.3.1-1.module+el8.4.0+15041+cb41100f.1', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-pip-wheel-19.3.1-1.module+el8.4.0+15041+cb41100f.1', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-ply-3.11-10.module+el8.4.0+9579+e9717e18', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-psutil-5.6.4-3.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-psutil-5.6.4-3.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-psycopg2-2.8.4-4.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-psycopg2-2.8.4-4.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-psycopg2-doc-2.8.4-4.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-psycopg2-doc-2.8.4-4.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-psycopg2-tests-2.8.4-4.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-psycopg2-tests-2.8.4-4.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-pycparser-2.19-3.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-PyMySQL-0.10.1-1.module+el8.4.0+9692+8e86ab84', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-pysocks-1.7.1-4.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-pytz-2019.3-3.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-pyyaml-5.4.1-1.module+el8.4.0+10706+5c295a3e', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-pyyaml-5.4.1-1.module+el8.4.0+10706+5c295a3e', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-requests-2.22.0-9.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-rpm-macros-3.8.6-3.module+el8.4.0+19187+74687b24.2', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-scipy-1.3.1-4.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-scipy-1.3.1-4.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-setuptools-41.6.0-4.module+el8.4.0+15041+cb41100f.1', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-setuptools-wheel-41.6.0-4.module+el8.4.0+15041+cb41100f.1', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-six-1.12.0-10.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-test-3.8.6-3.module+el8.4.0+19187+74687b24.2', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-test-3.8.6-3.module+el8.4.0+19187+74687b24.2', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-tkinter-3.8.6-3.module+el8.4.0+19187+74687b24.2', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-tkinter-3.8.6-3.module+el8.4.0+19187+74687b24.2', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-urllib3-1.25.7-4.module+el8.4.0+8888+89bc7e79', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-wheel-0.33.6-5.module+el8.4.0+15041+cb41100f.1', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-wheel-wheel-0.33.6-5.module+el8.4.0+15041+cb41100f.1', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/python38');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python38:3.8');
if ('3.8' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module python38:' + module_ver);

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
    foreach var module_array ( appstreams[module] ) {
      var repo_relative_urls = NULL;
      if (!empty_or_null(module_array['repo_relative_urls'])) repo_relative_urls = module_array['repo_relative_urls'];
      foreach var package_array ( module_array['pkgs'] ) {
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
        if (!empty_or_null(package_array['release'])) _release = 'RHEL' + package_array['release'];
        if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
        if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
        if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
        if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
        if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
        if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
        if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
        if (reference &&
            _release &&
            rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
            (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
            rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python38:3.8');

if (flag)
{
  var subscription_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in the Red Hat Enterprise Linux\n' +
    'Advanced Update Support, Telco Extended Update Support or Update Services for SAP Solutions repositories.\n' +
    'Access to these repositories requires a paid RHEL subscription.\n';
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = subscription_caveat + rpm_report_get() + redhat_report_repo_caveat();
  else extra = subscription_caveat + rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python38 / python38-Cython / python38-PyMySQL / python38-asn1crypto / etc');
}
