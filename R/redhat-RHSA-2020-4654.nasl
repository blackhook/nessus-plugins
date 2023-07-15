##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:4654. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142407);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id("CVE-2019-20907", "CVE-2019-20916");
  script_xref(name:"RHSA", value:"2020:4654");
  script_xref(name:"IAVA", value:"2020-A-0340-S");

  script_name(english:"RHEL 8 : python27:2.7 (RHSA-2020:4654)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:4654 advisory.

  - python: infinite loop in the tarfile module via crafted TAR archive (CVE-2019-20907)

  - python-pip: directory traversal in _download_http_url() function in src/pip/_internal/download.py
    (CVE-2019-20916)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-20907");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-20916");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:4654");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1856481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1868135");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20916");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 22, 835);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-nose-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-psycopg2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-sqlalchemy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-Cython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-attrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-backports");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-backports-ssl_match_hostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-coverage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-docs-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-docutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-funcsigs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-ipaddress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-markupsafe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-mock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-nose");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-numpy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-numpy-f2py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-pip-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-pluggy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-psycopg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-psycopg2-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-psycopg2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-pygments");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-pymongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-pymongo-gridfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-pysocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-pytest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-pytest-mock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-pytz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-pyyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-scipy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-setuptools-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-setuptools_scm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-six");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-sqlalchemy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-virtualenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-wheel-wheel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var appstreams = {
  'python27:2.7': [
    {
      'repo_relative_urls': [
        'content/aus/rhel8/8.4/x86_64/appstream/debug',
        'content/aus/rhel8/8.4/x86_64/appstream/os',
        'content/aus/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/aus/rhel8/8.4/x86_64/baseos/debug',
        'content/aus/rhel8/8.4/x86_64/baseos/os',
        'content/aus/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/aarch64/appstream/debug',
        'content/e4s/rhel8/8.4/aarch64/appstream/os',
        'content/e4s/rhel8/8.4/aarch64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/aarch64/baseos/debug',
        'content/e4s/rhel8/8.4/aarch64/baseos/os',
        'content/e4s/rhel8/8.4/aarch64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/appstream/debug',
        'content/e4s/rhel8/8.4/ppc64le/appstream/os',
        'content/e4s/rhel8/8.4/ppc64le/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/baseos/debug',
        'content/e4s/rhel8/8.4/ppc64le/baseos/os',
        'content/e4s/rhel8/8.4/ppc64le/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/highavailability/debug',
        'content/e4s/rhel8/8.4/ppc64le/highavailability/os',
        'content/e4s/rhel8/8.4/ppc64le/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/sap-solutions/debug',
        'content/e4s/rhel8/8.4/ppc64le/sap-solutions/os',
        'content/e4s/rhel8/8.4/ppc64le/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/sap/debug',
        'content/e4s/rhel8/8.4/ppc64le/sap/os',
        'content/e4s/rhel8/8.4/ppc64le/sap/source/SRPMS',
        'content/e4s/rhel8/8.4/s390x/appstream/debug',
        'content/e4s/rhel8/8.4/s390x/appstream/os',
        'content/e4s/rhel8/8.4/s390x/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/s390x/baseos/debug',
        'content/e4s/rhel8/8.4/s390x/baseos/os',
        'content/e4s/rhel8/8.4/s390x/baseos/source/SRPMS',
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
        'content/eus/rhel8/8.4/aarch64/appstream/debug',
        'content/eus/rhel8/8.4/aarch64/appstream/os',
        'content/eus/rhel8/8.4/aarch64/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/baseos/debug',
        'content/eus/rhel8/8.4/aarch64/baseos/os',
        'content/eus/rhel8/8.4/aarch64/baseos/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/codeready-builder/debug',
        'content/eus/rhel8/8.4/aarch64/codeready-builder/os',
        'content/eus/rhel8/8.4/aarch64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/highavailability/debug',
        'content/eus/rhel8/8.4/aarch64/highavailability/os',
        'content/eus/rhel8/8.4/aarch64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/supplementary/debug',
        'content/eus/rhel8/8.4/aarch64/supplementary/os',
        'content/eus/rhel8/8.4/aarch64/supplementary/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/appstream/debug',
        'content/eus/rhel8/8.4/ppc64le/appstream/os',
        'content/eus/rhel8/8.4/ppc64le/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/baseos/debug',
        'content/eus/rhel8/8.4/ppc64le/baseos/os',
        'content/eus/rhel8/8.4/ppc64le/baseos/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/codeready-builder/debug',
        'content/eus/rhel8/8.4/ppc64le/codeready-builder/os',
        'content/eus/rhel8/8.4/ppc64le/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/highavailability/debug',
        'content/eus/rhel8/8.4/ppc64le/highavailability/os',
        'content/eus/rhel8/8.4/ppc64le/highavailability/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/resilientstorage/debug',
        'content/eus/rhel8/8.4/ppc64le/resilientstorage/os',
        'content/eus/rhel8/8.4/ppc64le/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/sap-solutions/debug',
        'content/eus/rhel8/8.4/ppc64le/sap-solutions/os',
        'content/eus/rhel8/8.4/ppc64le/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/sap/debug',
        'content/eus/rhel8/8.4/ppc64le/sap/os',
        'content/eus/rhel8/8.4/ppc64le/sap/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/supplementary/debug',
        'content/eus/rhel8/8.4/ppc64le/supplementary/os',
        'content/eus/rhel8/8.4/ppc64le/supplementary/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/appstream/debug',
        'content/eus/rhel8/8.4/s390x/appstream/os',
        'content/eus/rhel8/8.4/s390x/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/baseos/debug',
        'content/eus/rhel8/8.4/s390x/baseos/os',
        'content/eus/rhel8/8.4/s390x/baseos/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/codeready-builder/debug',
        'content/eus/rhel8/8.4/s390x/codeready-builder/os',
        'content/eus/rhel8/8.4/s390x/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/highavailability/debug',
        'content/eus/rhel8/8.4/s390x/highavailability/os',
        'content/eus/rhel8/8.4/s390x/highavailability/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/resilientstorage/debug',
        'content/eus/rhel8/8.4/s390x/resilientstorage/os',
        'content/eus/rhel8/8.4/s390x/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/sap/debug',
        'content/eus/rhel8/8.4/s390x/sap/os',
        'content/eus/rhel8/8.4/s390x/sap/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/supplementary/debug',
        'content/eus/rhel8/8.4/s390x/supplementary/os',
        'content/eus/rhel8/8.4/s390x/supplementary/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/appstream/debug',
        'content/eus/rhel8/8.4/x86_64/appstream/os',
        'content/eus/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/baseos/debug',
        'content/eus/rhel8/8.4/x86_64/baseos/os',
        'content/eus/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/codeready-builder/debug',
        'content/eus/rhel8/8.4/x86_64/codeready-builder/os',
        'content/eus/rhel8/8.4/x86_64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/highavailability/debug',
        'content/eus/rhel8/8.4/x86_64/highavailability/os',
        'content/eus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/resilientstorage/debug',
        'content/eus/rhel8/8.4/x86_64/resilientstorage/os',
        'content/eus/rhel8/8.4/x86_64/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/sap-solutions/debug',
        'content/eus/rhel8/8.4/x86_64/sap-solutions/os',
        'content/eus/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/sap/debug',
        'content/eus/rhel8/8.4/x86_64/sap/os',
        'content/eus/rhel8/8.4/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/supplementary/debug',
        'content/eus/rhel8/8.4/x86_64/supplementary/os',
        'content/eus/rhel8/8.4/x86_64/supplementary/source/SRPMS',
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
        {'reference':'babel-2.5.1-9.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python-nose-docs-1.3.7-30.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python-psycopg2-doc-2.7.5-7.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python-sqlalchemy-doc-1.3.2-2.module+el8.3.0+6647+8d010749', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-2.7.17-2.module+el8.3.0+7681+f1f02ded', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-attrs-17.4.0-10.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-babel-2.5.1-9.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-backports-1.0-15.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-backports-ssl_match_hostname-3.5.0.1-11.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-bson-3.6.1-11.module+el8.1.0+3446+c3d52da3', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-chardet-3.0.4-10.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-coverage-4.5.1-4.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-Cython-0.28.1-7.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-debug-2.7.17-2.module+el8.3.0+7681+f1f02ded', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-devel-2.7.17-2.module+el8.3.0+7681+f1f02ded', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-dns-1.15.0-10.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-docs-2.7.16-2.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-docs-info-2.7.16-2.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-docutils-0.14-12.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-funcsigs-1.0.2-13.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-idna-2.5-7.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-ipaddress-1.0.18-6.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-jinja2-2.10-8.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-libs-2.7.17-2.module+el8.3.0+7681+f1f02ded', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-lxml-4.2.3-3.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-markupsafe-0.23-19.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-mock-2.0.0-13.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-nose-1.3.7-30.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-numpy-1.14.2-13.module+el8.1.0+3323+7ac3e00f', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'python2-numpy-doc-1.14.2-13.module+el8.1.0+3323+7ac3e00f', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'python2-numpy-f2py-1.14.2-13.module+el8.1.0+3323+7ac3e00f', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'python2-pip-9.0.3-18.module+el8.3.0+7707+eb4bba01', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pip-wheel-9.0.3-18.module+el8.3.0+7707+eb4bba01', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pluggy-0.6.0-8.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-psycopg2-2.7.5-7.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-psycopg2-debug-2.7.5-7.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-psycopg2-tests-2.7.5-7.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-py-1.5.3-6.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pygments-2.2.0-20.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pymongo-3.6.1-11.module+el8.1.0+3446+c3d52da3', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pymongo-gridfs-3.6.1-11.module+el8.1.0+3446+c3d52da3', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-PyMySQL-0.8.0-10.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pysocks-1.6.8-6.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pytest-3.4.2-13.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pytest-mock-1.9.0-4.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pytz-2017.2-12.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pyyaml-3.12-16.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-requests-2.20.0-3.module+el8.2.0+4577+feefd9b8', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-rpm-macros-3-38.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-scipy-1.0.0-20.module+el8.1.0+3323+7ac3e00f', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-setuptools-39.0.1-12.module+el8.3.0+7075+8484f0d0', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-setuptools-wheel-39.0.1-12.module+el8.3.0+7075+8484f0d0', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-setuptools_scm-1.15.7-6.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-six-1.11.0-5.module+el8.1.0+3111+de3f2d8e', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-sqlalchemy-1.3.2-2.module+el8.3.0+6647+8d010749', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-test-2.7.17-2.module+el8.3.0+7681+f1f02ded', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-tkinter-2.7.17-2.module+el8.3.0+7681+f1f02ded', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-tools-2.7.17-2.module+el8.3.0+7681+f1f02ded', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-urllib3-1.24.2-1.module+el8.1.0+3280+19512f10', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-virtualenv-15.1.0-19.module+el8.1.0+3507+d69c168d', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-wheel-0.31.1-2.module+el8.1.0+3725+aac5cd17', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'python2-wheel-wheel-0.31.1-2.module+el8.1.0+3725+aac5cd17', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
      ]
    },
    {
      'repo_relative_urls': [
        'content/aus/rhel8/8.6/x86_64/appstream/debug',
        'content/aus/rhel8/8.6/x86_64/appstream/os',
        'content/aus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/aus/rhel8/8.6/x86_64/baseos/debug',
        'content/aus/rhel8/8.6/x86_64/baseos/os',
        'content/aus/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/appstream/debug',
        'content/e4s/rhel8/8.6/ppc64le/appstream/os',
        'content/e4s/rhel8/8.6/ppc64le/appstream/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/baseos/debug',
        'content/e4s/rhel8/8.6/ppc64le/baseos/os',
        'content/e4s/rhel8/8.6/ppc64le/baseos/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/highavailability/debug',
        'content/e4s/rhel8/8.6/ppc64le/highavailability/os',
        'content/e4s/rhel8/8.6/ppc64le/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/sap-solutions/debug',
        'content/e4s/rhel8/8.6/ppc64le/sap-solutions/os',
        'content/e4s/rhel8/8.6/ppc64le/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/sap/debug',
        'content/e4s/rhel8/8.6/ppc64le/sap/os',
        'content/e4s/rhel8/8.6/ppc64le/sap/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/appstream/debug',
        'content/e4s/rhel8/8.6/x86_64/appstream/os',
        'content/e4s/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/baseos/debug',
        'content/e4s/rhel8/8.6/x86_64/baseos/os',
        'content/e4s/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/highavailability/debug',
        'content/e4s/rhel8/8.6/x86_64/highavailability/os',
        'content/e4s/rhel8/8.6/x86_64/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/sap-solutions/debug',
        'content/e4s/rhel8/8.6/x86_64/sap-solutions/os',
        'content/e4s/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/sap/debug',
        'content/e4s/rhel8/8.6/x86_64/sap/os',
        'content/e4s/rhel8/8.6/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/appstream/debug',
        'content/eus/rhel8/8.6/aarch64/appstream/os',
        'content/eus/rhel8/8.6/aarch64/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/baseos/debug',
        'content/eus/rhel8/8.6/aarch64/baseos/os',
        'content/eus/rhel8/8.6/aarch64/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/codeready-builder/debug',
        'content/eus/rhel8/8.6/aarch64/codeready-builder/os',
        'content/eus/rhel8/8.6/aarch64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/highavailability/debug',
        'content/eus/rhel8/8.6/aarch64/highavailability/os',
        'content/eus/rhel8/8.6/aarch64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/supplementary/debug',
        'content/eus/rhel8/8.6/aarch64/supplementary/os',
        'content/eus/rhel8/8.6/aarch64/supplementary/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/appstream/debug',
        'content/eus/rhel8/8.6/ppc64le/appstream/os',
        'content/eus/rhel8/8.6/ppc64le/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/baseos/debug',
        'content/eus/rhel8/8.6/ppc64le/baseos/os',
        'content/eus/rhel8/8.6/ppc64le/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/codeready-builder/debug',
        'content/eus/rhel8/8.6/ppc64le/codeready-builder/os',
        'content/eus/rhel8/8.6/ppc64le/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/highavailability/debug',
        'content/eus/rhel8/8.6/ppc64le/highavailability/os',
        'content/eus/rhel8/8.6/ppc64le/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/resilientstorage/debug',
        'content/eus/rhel8/8.6/ppc64le/resilientstorage/os',
        'content/eus/rhel8/8.6/ppc64le/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/sap-solutions/debug',
        'content/eus/rhel8/8.6/ppc64le/sap-solutions/os',
        'content/eus/rhel8/8.6/ppc64le/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/sap/debug',
        'content/eus/rhel8/8.6/ppc64le/sap/os',
        'content/eus/rhel8/8.6/ppc64le/sap/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/supplementary/debug',
        'content/eus/rhel8/8.6/ppc64le/supplementary/os',
        'content/eus/rhel8/8.6/ppc64le/supplementary/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/appstream/debug',
        'content/eus/rhel8/8.6/s390x/appstream/os',
        'content/eus/rhel8/8.6/s390x/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/baseos/debug',
        'content/eus/rhel8/8.6/s390x/baseos/os',
        'content/eus/rhel8/8.6/s390x/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/codeready-builder/debug',
        'content/eus/rhel8/8.6/s390x/codeready-builder/os',
        'content/eus/rhel8/8.6/s390x/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/highavailability/debug',
        'content/eus/rhel8/8.6/s390x/highavailability/os',
        'content/eus/rhel8/8.6/s390x/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/resilientstorage/debug',
        'content/eus/rhel8/8.6/s390x/resilientstorage/os',
        'content/eus/rhel8/8.6/s390x/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/sap/debug',
        'content/eus/rhel8/8.6/s390x/sap/os',
        'content/eus/rhel8/8.6/s390x/sap/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/supplementary/debug',
        'content/eus/rhel8/8.6/s390x/supplementary/os',
        'content/eus/rhel8/8.6/s390x/supplementary/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/appstream/debug',
        'content/eus/rhel8/8.6/x86_64/appstream/os',
        'content/eus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/baseos/debug',
        'content/eus/rhel8/8.6/x86_64/baseos/os',
        'content/eus/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/codeready-builder/debug',
        'content/eus/rhel8/8.6/x86_64/codeready-builder/os',
        'content/eus/rhel8/8.6/x86_64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/highavailability/debug',
        'content/eus/rhel8/8.6/x86_64/highavailability/os',
        'content/eus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/resilientstorage/debug',
        'content/eus/rhel8/8.6/x86_64/resilientstorage/os',
        'content/eus/rhel8/8.6/x86_64/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/sap-solutions/debug',
        'content/eus/rhel8/8.6/x86_64/sap-solutions/os',
        'content/eus/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/sap/debug',
        'content/eus/rhel8/8.6/x86_64/sap/os',
        'content/eus/rhel8/8.6/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/supplementary/debug',
        'content/eus/rhel8/8.6/x86_64/supplementary/os',
        'content/eus/rhel8/8.6/x86_64/supplementary/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/appstream/debug',
        'content/tus/rhel8/8.6/x86_64/appstream/os',
        'content/tus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/baseos/debug',
        'content/tus/rhel8/8.6/x86_64/baseos/os',
        'content/tus/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/highavailability/debug',
        'content/tus/rhel8/8.6/x86_64/highavailability/os',
        'content/tus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/rt/os',
        'content/tus/rhel8/8.6/x86_64/rt/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'babel-2.5.1-9.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python-nose-docs-1.3.7-30.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python-psycopg2-doc-2.7.5-7.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python-sqlalchemy-doc-1.3.2-2.module+el8.3.0+6647+8d010749', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-2.7.17-2.module+el8.3.0+7681+f1f02ded', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-attrs-17.4.0-10.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-babel-2.5.1-9.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-backports-1.0-15.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-backports-ssl_match_hostname-3.5.0.1-11.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-bson-3.6.1-11.module+el8.1.0+3446+c3d52da3', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-chardet-3.0.4-10.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-coverage-4.5.1-4.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-Cython-0.28.1-7.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-debug-2.7.17-2.module+el8.3.0+7681+f1f02ded', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-devel-2.7.17-2.module+el8.3.0+7681+f1f02ded', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-dns-1.15.0-10.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-docs-2.7.16-2.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-docs-info-2.7.16-2.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-docutils-0.14-12.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-funcsigs-1.0.2-13.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-idna-2.5-7.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-ipaddress-1.0.18-6.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-jinja2-2.10-8.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-libs-2.7.17-2.module+el8.3.0+7681+f1f02ded', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-lxml-4.2.3-3.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-markupsafe-0.23-19.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-mock-2.0.0-13.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-nose-1.3.7-30.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-numpy-1.14.2-13.module+el8.1.0+3323+7ac3e00f', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'python2-numpy-doc-1.14.2-13.module+el8.1.0+3323+7ac3e00f', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'python2-numpy-f2py-1.14.2-13.module+el8.1.0+3323+7ac3e00f', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'python2-pip-9.0.3-18.module+el8.3.0+7707+eb4bba01', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pip-wheel-9.0.3-18.module+el8.3.0+7707+eb4bba01', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pluggy-0.6.0-8.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-psycopg2-2.7.5-7.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-psycopg2-debug-2.7.5-7.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-psycopg2-tests-2.7.5-7.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-py-1.5.3-6.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pygments-2.2.0-20.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pymongo-3.6.1-11.module+el8.1.0+3446+c3d52da3', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pymongo-gridfs-3.6.1-11.module+el8.1.0+3446+c3d52da3', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-PyMySQL-0.8.0-10.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pysocks-1.6.8-6.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pytest-3.4.2-13.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pytest-mock-1.9.0-4.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pytz-2017.2-12.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pyyaml-3.12-16.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-requests-2.20.0-3.module+el8.2.0+4577+feefd9b8', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-rpm-macros-3-38.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-scipy-1.0.0-20.module+el8.1.0+3323+7ac3e00f', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-setuptools-39.0.1-12.module+el8.3.0+7075+8484f0d0', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-setuptools-wheel-39.0.1-12.module+el8.3.0+7075+8484f0d0', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-setuptools_scm-1.15.7-6.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-six-1.11.0-5.module+el8.1.0+3111+de3f2d8e', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-sqlalchemy-1.3.2-2.module+el8.3.0+6647+8d010749', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-test-2.7.17-2.module+el8.3.0+7681+f1f02ded', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-tkinter-2.7.17-2.module+el8.3.0+7681+f1f02ded', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-tools-2.7.17-2.module+el8.3.0+7681+f1f02ded', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-urllib3-1.24.2-1.module+el8.1.0+3280+19512f10', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-virtualenv-15.1.0-19.module+el8.1.0+3507+d69c168d', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-wheel-0.31.1-2.module+el8.1.0+3725+aac5cd17', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'python2-wheel-wheel-0.31.1-2.module+el8.1.0+3725+aac5cd17', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
      ]
    },
    {
      'repo_relative_urls': [
        'content/dist/rhel8/8/aarch64/appstream/debug',
        'content/dist/rhel8/8/aarch64/appstream/os',
        'content/dist/rhel8/8/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8/aarch64/baseos/debug',
        'content/dist/rhel8/8/aarch64/baseos/os',
        'content/dist/rhel8/8/aarch64/baseos/source/SRPMS',
        'content/dist/rhel8/8/aarch64/codeready-builder/debug',
        'content/dist/rhel8/8/aarch64/codeready-builder/os',
        'content/dist/rhel8/8/aarch64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/aarch64/highavailability/debug',
        'content/dist/rhel8/8/aarch64/highavailability/os',
        'content/dist/rhel8/8/aarch64/highavailability/source/SRPMS',
        'content/dist/rhel8/8/aarch64/supplementary/debug',
        'content/dist/rhel8/8/aarch64/supplementary/os',
        'content/dist/rhel8/8/aarch64/supplementary/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/appstream/debug',
        'content/dist/rhel8/8/ppc64le/appstream/os',
        'content/dist/rhel8/8/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/baseos/debug',
        'content/dist/rhel8/8/ppc64le/baseos/os',
        'content/dist/rhel8/8/ppc64le/baseos/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/codeready-builder/debug',
        'content/dist/rhel8/8/ppc64le/codeready-builder/os',
        'content/dist/rhel8/8/ppc64le/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/highavailability/debug',
        'content/dist/rhel8/8/ppc64le/highavailability/os',
        'content/dist/rhel8/8/ppc64le/highavailability/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/resilientstorage/debug',
        'content/dist/rhel8/8/ppc64le/resilientstorage/os',
        'content/dist/rhel8/8/ppc64le/resilientstorage/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/sap-solutions/debug',
        'content/dist/rhel8/8/ppc64le/sap-solutions/os',
        'content/dist/rhel8/8/ppc64le/sap-solutions/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/sap/debug',
        'content/dist/rhel8/8/ppc64le/sap/os',
        'content/dist/rhel8/8/ppc64le/sap/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/supplementary/debug',
        'content/dist/rhel8/8/ppc64le/supplementary/os',
        'content/dist/rhel8/8/ppc64le/supplementary/source/SRPMS',
        'content/dist/rhel8/8/s390x/appstream/debug',
        'content/dist/rhel8/8/s390x/appstream/os',
        'content/dist/rhel8/8/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8/s390x/baseos/debug',
        'content/dist/rhel8/8/s390x/baseos/os',
        'content/dist/rhel8/8/s390x/baseos/source/SRPMS',
        'content/dist/rhel8/8/s390x/codeready-builder/debug',
        'content/dist/rhel8/8/s390x/codeready-builder/os',
        'content/dist/rhel8/8/s390x/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/s390x/highavailability/debug',
        'content/dist/rhel8/8/s390x/highavailability/os',
        'content/dist/rhel8/8/s390x/highavailability/source/SRPMS',
        'content/dist/rhel8/8/s390x/resilientstorage/debug',
        'content/dist/rhel8/8/s390x/resilientstorage/os',
        'content/dist/rhel8/8/s390x/resilientstorage/source/SRPMS',
        'content/dist/rhel8/8/s390x/sap/debug',
        'content/dist/rhel8/8/s390x/sap/os',
        'content/dist/rhel8/8/s390x/sap/source/SRPMS',
        'content/dist/rhel8/8/s390x/supplementary/debug',
        'content/dist/rhel8/8/s390x/supplementary/os',
        'content/dist/rhel8/8/s390x/supplementary/source/SRPMS',
        'content/dist/rhel8/8/x86_64/appstream/debug',
        'content/dist/rhel8/8/x86_64/appstream/os',
        'content/dist/rhel8/8/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8/x86_64/baseos/debug',
        'content/dist/rhel8/8/x86_64/baseos/os',
        'content/dist/rhel8/8/x86_64/baseos/source/SRPMS',
        'content/dist/rhel8/8/x86_64/codeready-builder/debug',
        'content/dist/rhel8/8/x86_64/codeready-builder/os',
        'content/dist/rhel8/8/x86_64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/x86_64/highavailability/debug',
        'content/dist/rhel8/8/x86_64/highavailability/os',
        'content/dist/rhel8/8/x86_64/highavailability/source/SRPMS',
        'content/dist/rhel8/8/x86_64/nfv/debug',
        'content/dist/rhel8/8/x86_64/nfv/os',
        'content/dist/rhel8/8/x86_64/nfv/source/SRPMS',
        'content/dist/rhel8/8/x86_64/resilientstorage/debug',
        'content/dist/rhel8/8/x86_64/resilientstorage/os',
        'content/dist/rhel8/8/x86_64/resilientstorage/source/SRPMS',
        'content/dist/rhel8/8/x86_64/rt/debug',
        'content/dist/rhel8/8/x86_64/rt/os',
        'content/dist/rhel8/8/x86_64/rt/source/SRPMS',
        'content/dist/rhel8/8/x86_64/sap-solutions/debug',
        'content/dist/rhel8/8/x86_64/sap-solutions/os',
        'content/dist/rhel8/8/x86_64/sap-solutions/source/SRPMS',
        'content/dist/rhel8/8/x86_64/sap/debug',
        'content/dist/rhel8/8/x86_64/sap/os',
        'content/dist/rhel8/8/x86_64/sap/source/SRPMS',
        'content/dist/rhel8/8/x86_64/supplementary/debug',
        'content/dist/rhel8/8/x86_64/supplementary/os',
        'content/dist/rhel8/8/x86_64/supplementary/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'babel-2.5.1-9.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python-nose-docs-1.3.7-30.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python-psycopg2-doc-2.7.5-7.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python-sqlalchemy-doc-1.3.2-2.module+el8.3.0+6647+8d010749', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-2.7.17-2.module+el8.3.0+7681+f1f02ded', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-attrs-17.4.0-10.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-babel-2.5.1-9.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-backports-1.0-15.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-backports-ssl_match_hostname-3.5.0.1-11.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-bson-3.6.1-11.module+el8.1.0+3446+c3d52da3', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-chardet-3.0.4-10.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-coverage-4.5.1-4.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-Cython-0.28.1-7.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-debug-2.7.17-2.module+el8.3.0+7681+f1f02ded', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-devel-2.7.17-2.module+el8.3.0+7681+f1f02ded', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-dns-1.15.0-10.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-docs-2.7.16-2.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-docs-info-2.7.16-2.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-docutils-0.14-12.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-funcsigs-1.0.2-13.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-idna-2.5-7.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-ipaddress-1.0.18-6.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-jinja2-2.10-8.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-libs-2.7.17-2.module+el8.3.0+7681+f1f02ded', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-lxml-4.2.3-3.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-markupsafe-0.23-19.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-mock-2.0.0-13.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-nose-1.3.7-30.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-numpy-1.14.2-13.module+el8.1.0+3323+7ac3e00f', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'python2-numpy-doc-1.14.2-13.module+el8.1.0+3323+7ac3e00f', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'python2-numpy-f2py-1.14.2-13.module+el8.1.0+3323+7ac3e00f', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'python2-pip-9.0.3-18.module+el8.3.0+7707+eb4bba01', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pip-wheel-9.0.3-18.module+el8.3.0+7707+eb4bba01', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pluggy-0.6.0-8.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-psycopg2-2.7.5-7.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-psycopg2-debug-2.7.5-7.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-psycopg2-tests-2.7.5-7.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-py-1.5.3-6.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pygments-2.2.0-20.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pymongo-3.6.1-11.module+el8.1.0+3446+c3d52da3', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pymongo-gridfs-3.6.1-11.module+el8.1.0+3446+c3d52da3', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-PyMySQL-0.8.0-10.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pysocks-1.6.8-6.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pytest-3.4.2-13.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pytest-mock-1.9.0-4.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pytz-2017.2-12.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-pyyaml-3.12-16.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-requests-2.20.0-3.module+el8.2.0+4577+feefd9b8', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-rpm-macros-3-38.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-scipy-1.0.0-20.module+el8.1.0+3323+7ac3e00f', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-setuptools-39.0.1-12.module+el8.3.0+7075+8484f0d0', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-setuptools-wheel-39.0.1-12.module+el8.3.0+7075+8484f0d0', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-setuptools_scm-1.15.7-6.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-six-1.11.0-5.module+el8.1.0+3111+de3f2d8e', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-sqlalchemy-1.3.2-2.module+el8.3.0+6647+8d010749', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-test-2.7.17-2.module+el8.3.0+7681+f1f02ded', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-tkinter-2.7.17-2.module+el8.3.0+7681+f1f02ded', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-tools-2.7.17-2.module+el8.3.0+7681+f1f02ded', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-urllib3-1.24.2-1.module+el8.1.0+3280+19512f10', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-virtualenv-15.1.0-19.module+el8.1.0+3507+d69c168d', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python2-wheel-0.31.1-2.module+el8.1.0+3725+aac5cd17', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'python2-wheel-wheel-0.31.1-2.module+el8.1.0+3725+aac5cd17', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/python27');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python27:2.7');
if ('2.7' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module python27:' + module_ver);

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
      var enterprise_linux_flag = rhel_repo_urls_has_content_dist_rhel(repo_urls:repo_relative_urls);
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
        if (!empty_or_null(package_array['sp']) && !enterprise_linux_flag) sp = package_array['sp'];
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python27:2.7');

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'babel / python-nose-docs / python-psycopg2-doc / python-sqlalchemy-doc / etc');
}
