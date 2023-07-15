#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-4160.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155967);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/28");

  script_cve_id(
    "CVE-2021-3426",
    "CVE-2021-3572",
    "CVE-2021-3733",
    "CVE-2021-3737",
    "CVE-2021-28957",
    "CVE-2021-29921",
    "CVE-2021-33503"
  );
  script_xref(name:"IAVA", value:"2021-A-0263-S");
  script_xref(name:"IAVA", value:"2021-A-0497-S");

  script_name(english:"Oracle Linux 8 : python39:3.9 / and / python39-devel:3.9 (ELSA-2021-4160)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-4160 advisory.

  - python: urllib: Regular expression DoS in AbstractBasicAuthHandler (CVE-2021-3733)

  - A flaw was found in python-pip in the way it handled Unicode separators in git references. A remote
    attacker could possibly use this issue to install a different revision on a repository. The highest threat
    from this vulnerability is to data integrity. This is fixed in python-pip version 21.1. (CVE-2021-3572)

  - There's a flaw in Python 3's pydoc. A local or adjacent attacker who discovers or is able to convince
    another local or adjacent user to start a pydoc server could access the server and use it to disclose
    sensitive information belonging to the other user that they would not normally be able to access. The
    highest risk of this flaw is to data confidentiality. This flaw affects Python versions before 3.8.9,
    Python versions before 3.9.3 and Python versions before 3.10.0a7. (CVE-2021-3426)

  - An XSS vulnerability was discovered in python-lxml's clean module versions before 4.6.3. When disabling
    the safe_attrs_only and forms arguments, the Cleaner class does not remove the formaction attribute
    allowing for JS to bypass the sanitizer. A remote attacker could exploit this flaw to run arbitrary JS
    code on users who interact with incorrectly sanitized HTML. This issue is patched in lxml 4.6.3.
    (CVE-2021-28957)

  - An issue was discovered in urllib3 before 1.26.5. When provided with a URL containing many @ characters in
    the authority component, the authority regular expression exhibits catastrophic backtracking, causing a
    denial of service if a URL were passed as a parameter or redirected to via an HTTP redirect.
    (CVE-2021-33503)

  - python: urllib: HTTP client possible infinite loop on a 100 Continue response (CVE-2021-3737)

  - In Python before 3,9,5, the ipaddress library mishandles leading zero characters in the octets of an IP
    address string. This (in some situations) allows attackers to bypass access control that is based on IP
    addresses. (CVE-2021-29921)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-4160.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29921");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-Cython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-attrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-cffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-iniconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-mod_wsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-more-itertools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-numpy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-numpy-f2py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-packaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-pip-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-pluggy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-ply");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-psutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-psycopg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-psycopg2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-psycopg2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-pybind11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-pybind11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-pycparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-pyparsing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-pysocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-pytest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-pyyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-scipy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-setuptools-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-six");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-toml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-wcwidth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-wheel-wheel");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
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

var module_ver = get_kb_item('Host/RedHat/appstream/python39');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python39:3.9');
if ('3.9' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module python39:' + module_ver);

var appstreams = {
    'python39:3.9': [
      {'reference':'python39-3.9.6-2.module+el8.5.0+20364+c7fe1181', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-3.9.6-2.module+el8.5.0+20364+c7fe1181', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-attrs-20.3.0-2.module+el8.4.0+20109+b7b1db01', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cffi-1.14.3-2.module+el8.4.0+20109+b7b1db01', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cffi-1.14.3-2.module+el8.4.0+20109+b7b1db01', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-chardet-3.0.4-19.module+el8.4.0+20109+b7b1db01', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cryptography-3.3.1-2.module+el8.4.0+20109+b7b1db01', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cryptography-3.3.1-2.module+el8.4.0+20109+b7b1db01', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-Cython-0.29.21-5.module+el8.4.0+20109+b7b1db01', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-Cython-0.29.21-5.module+el8.4.0+20109+b7b1db01', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-debug-3.9.6-2.module+el8.5.0+20364+c7fe1181', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-debug-3.9.6-2.module+el8.5.0+20364+c7fe1181', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-devel-3.9.6-2.module+el8.5.0+20364+c7fe1181', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-devel-3.9.6-2.module+el8.5.0+20364+c7fe1181', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-idle-3.9.6-2.module+el8.5.0+20364+c7fe1181', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-idle-3.9.6-2.module+el8.5.0+20364+c7fe1181', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-idna-2.10-3.module+el8.4.0+20109+b7b1db01', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-iniconfig-1.1.1-2.module+el8.4.0+20109+b7b1db01', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-libs-3.9.6-2.module+el8.5.0+20364+c7fe1181', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-libs-3.9.6-2.module+el8.5.0+20364+c7fe1181', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-lxml-4.6.2-3.module+el8.5.0+20364+c7fe1181', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-lxml-4.6.2-3.module+el8.5.0+20364+c7fe1181', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-mod_wsgi-4.7.1-4.module+el8.4.0+20109+b7b1db01', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-mod_wsgi-4.7.1-4.module+el8.4.0+20109+b7b1db01', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-more-itertools-8.5.0-2.module+el8.4.0+20109+b7b1db01', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-1.19.4-3.module+el8.5.0+20364+c7fe1181', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-1.19.4-3.module+el8.5.0+20364+c7fe1181', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-doc-1.19.4-3.module+el8.5.0+20364+c7fe1181', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-f2py-1.19.4-3.module+el8.5.0+20364+c7fe1181', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-f2py-1.19.4-3.module+el8.5.0+20364+c7fe1181', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-packaging-20.4-4.module+el8.4.0+20109+b7b1db01', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pip-20.2.4-6.module+el8.5.0+20364+c7fe1181', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pip-wheel-20.2.4-6.module+el8.5.0+20364+c7fe1181', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pluggy-0.13.1-3.module+el8.4.0+20109+b7b1db01', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-ply-3.11-10.module+el8.4.0+20109+b7b1db01', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psutil-5.8.0-4.module+el8.4.0+20109+b7b1db01', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psutil-5.8.0-4.module+el8.4.0+20109+b7b1db01', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-2.8.6-2.module+el8.4.0+20109+b7b1db01', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-2.8.6-2.module+el8.4.0+20109+b7b1db01', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-doc-2.8.6-2.module+el8.4.0+20109+b7b1db01', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-doc-2.8.6-2.module+el8.4.0+20109+b7b1db01', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-tests-2.8.6-2.module+el8.4.0+20109+b7b1db01', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-tests-2.8.6-2.module+el8.4.0+20109+b7b1db01', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-py-1.10.0-1.module+el8.4.0+20109+b7b1db01', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pybind11-2.6.1-2.module+el8.4.0+20109+b7b1db01', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pybind11-2.6.1-2.module+el8.4.0+20109+b7b1db01', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pybind11-devel-2.6.1-2.module+el8.4.0+20109+b7b1db01', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pybind11-devel-2.6.1-2.module+el8.4.0+20109+b7b1db01', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pycparser-2.20-3.module+el8.4.0+20109+b7b1db01', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-PyMySQL-0.10.1-2.module+el8.4.0+20109+b7b1db01', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pyparsing-2.4.7-5.module+el8.4.0+20109+b7b1db01', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pysocks-1.7.1-4.module+el8.4.0+20109+b7b1db01', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pytest-6.0.2-2.module+el8.4.0+20109+b7b1db01', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pyyaml-5.4.1-1.module+el8.5.0+20364+c7fe1181', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pyyaml-5.4.1-1.module+el8.5.0+20364+c7fe1181', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-requests-2.25.0-2.module+el8.4.0+20109+b7b1db01', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-rpm-macros-3.9.6-2.module+el8.5.0+20364+c7fe1181', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-scipy-1.5.4-3.module+el8.4.0+20109+b7b1db01', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-scipy-1.5.4-3.module+el8.4.0+20109+b7b1db01', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-setuptools-50.3.2-4.module+el8.5.0+20364+c7fe1181', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-setuptools-wheel-50.3.2-4.module+el8.5.0+20364+c7fe1181', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-six-1.15.0-3.module+el8.4.0+20109+b7b1db01', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-test-3.9.6-2.module+el8.5.0+20364+c7fe1181', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-test-3.9.6-2.module+el8.5.0+20364+c7fe1181', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-tkinter-3.9.6-2.module+el8.5.0+20364+c7fe1181', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-tkinter-3.9.6-2.module+el8.5.0+20364+c7fe1181', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-toml-0.10.1-5.module+el8.4.0+20109+b7b1db01', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-urllib3-1.25.10-4.module+el8.5.0+20364+c7fe1181', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-wcwidth-0.2.5-3.module+el8.4.0+20109+b7b1db01', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-wheel-0.35.1-4.module+el8.5.0+20364+c7fe1181', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python39-wheel-wheel-0.35.1-4.module+el8.5.0+20364+c7fe1181', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
      var release = NULL;
      var sp = NULL;
      var cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
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
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python39:3.9');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python39 / python39-Cython / python39-PyMySQL / etc');
}
