#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2022:7593.
##

include('compat.inc');

if (description)
{
  script_id(170776);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2015-20107");
  script_xref(name:"RLSA", value:"2022:7593");

  script_name(english:"Rocky Linux 8 : python27:2.7 (RLSA-2022:7593)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2022:7593 advisory.

  - In Python (aka CPython) up to 3.10.8, the mailcap module does not add escape characters into commands
    discovered in the system mailcap file. This may allow attackers to inject shell commands into applications
    that call mailcap.findmatch with untrusted input (if they lack validation of user-provided filenames or
    arguments). The fix is also back-ported to 3.7, 3.8, 3.9 (CVE-2015-20107)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2022:7593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2075390");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-20107");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:Cython-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:PyYAML-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:numpy-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-coverage-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-nose-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-psycopg2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-psycopg2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-psycopg2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-pymongo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-pymongo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-sqlalchemy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-Cython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-Cython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-attrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-backports");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-backports-ssl_match_hostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-bson-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-coverage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-coverage-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-docs-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-funcsigs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-markupsafe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-mock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-nose");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-numpy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-numpy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-numpy-f2py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-pluggy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-psycopg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-psycopg2-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-psycopg2-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-psycopg2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-psycopg2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-pygments");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-pymongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-pymongo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-pymongo-gridfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-pysocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-pytest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-pytz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-pyyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-pyyaml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-scipy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-scipy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-setuptools-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-six");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-virtualenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-wheel-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-docutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-sqlalchemy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:scipy-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'babel-2.5.1-10.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'Cython-debugsource-0.28.1-7.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'Cython-debugsource-0.28.1-7.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'numpy-debugsource-1.14.2-16.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'numpy-debugsource-1.14.2-16.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python-coverage-debugsource-4.5.1-4.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-coverage-debugsource-4.5.1-4.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-nose-docs-1.3.7-31.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-psycopg2-debuginfo-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-psycopg2-debuginfo-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-psycopg2-debugsource-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-psycopg2-debugsource-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-psycopg2-doc-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-psycopg2-doc-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-pymongo-debuginfo-3.7.0-1.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-pymongo-debuginfo-3.7.0-1.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-pymongo-debugsource-3.7.0-1.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-pymongo-debugsource-3.7.0-1.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-sqlalchemy-doc-1.3.2-2.module+el8.4.0+597+ddf0ddea', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-2.7.18-11.module+el8.7.0+1062+663ba31c.rocky.0.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-2.7.18-11.module+el8.7.0+1062+663ba31c.rocky.0.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-attrs-17.4.0-10.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-babel-2.5.1-10.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-backports-1.0-16.module+el8.4.0+403+9ae17a31', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-backports-1.0-16.module+el8.4.0+403+9ae17a31', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-backports-ssl_match_hostname-3.5.0.1-12.module+el8.4.0+403+9ae17a31', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-bson-3.7.0-1.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-bson-3.7.0-1.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-bson-debuginfo-3.7.0-1.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-bson-debuginfo-3.7.0-1.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-chardet-3.0.4-10.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-coverage-4.5.1-4.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-coverage-4.5.1-4.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-coverage-debuginfo-4.5.1-4.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-coverage-debuginfo-4.5.1-4.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-Cython-0.28.1-7.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-Cython-0.28.1-7.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-Cython-debuginfo-0.28.1-7.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-Cython-debuginfo-0.28.1-7.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-debug-2.7.18-11.module+el8.7.0+1062+663ba31c.rocky.0.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-debug-2.7.18-11.module+el8.7.0+1062+663ba31c.rocky.0.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-debuginfo-2.7.18-11.module+el8.7.0+1062+663ba31c.rocky.0.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-debuginfo-2.7.18-11.module+el8.7.0+1062+663ba31c.rocky.0.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-debugsource-2.7.18-11.module+el8.7.0+1062+663ba31c.rocky.0.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-debugsource-2.7.18-11.module+el8.7.0+1062+663ba31c.rocky.0.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-devel-2.7.18-11.module+el8.7.0+1062+663ba31c.rocky.0.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-devel-2.7.18-11.module+el8.7.0+1062+663ba31c.rocky.0.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-dns-1.15.0-10.module+el8.7.0+1062+663ba31c', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-docs-2.7.16-2.module+el8.4.0+403+9ae17a31', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-docs-info-2.7.16-2.module+el8.4.0+403+9ae17a31', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-funcsigs-1.0.2-13.module+el8.4.0+403+9ae17a31', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-idna-2.5-7.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-jinja2-2.10-9.module+el8.7.0+1062+663ba31c', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-libs-2.7.18-11.module+el8.7.0+1062+663ba31c.rocky.0.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-libs-2.7.18-11.module+el8.7.0+1062+663ba31c.rocky.0.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-markupsafe-0.23-19.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-markupsafe-0.23-19.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-mock-2.0.0-13.module+el8.4.0+403+9ae17a31', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-nose-1.3.7-31.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-numpy-1.14.2-16.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python2-numpy-1.14.2-16.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python2-numpy-debuginfo-1.14.2-16.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python2-numpy-debuginfo-1.14.2-16.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python2-numpy-doc-1.14.2-16.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python2-numpy-f2py-1.14.2-16.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python2-numpy-f2py-1.14.2-16.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python2-pluggy-0.6.0-8.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-psycopg2-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-psycopg2-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-psycopg2-debug-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-psycopg2-debug-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-psycopg2-debug-debuginfo-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-psycopg2-debug-debuginfo-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-psycopg2-debuginfo-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-psycopg2-debuginfo-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-psycopg2-tests-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-psycopg2-tests-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-py-1.5.3-6.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pygments-2.2.0-22.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pymongo-3.7.0-1.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pymongo-3.7.0-1.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pymongo-debuginfo-3.7.0-1.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pymongo-debuginfo-3.7.0-1.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pymongo-gridfs-3.7.0-1.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pymongo-gridfs-3.7.0-1.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-PyMySQL-0.8.0-10.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pysocks-1.6.8-6.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pytest-3.4.2-13.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pytz-2017.2-12.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pyyaml-3.12-16.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pyyaml-3.12-16.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pyyaml-debuginfo-3.12-16.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-pyyaml-debuginfo-3.12-16.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-requests-2.20.0-3.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-scipy-1.0.0-21.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-scipy-1.0.0-21.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-scipy-debuginfo-1.0.0-21.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-scipy-debuginfo-1.0.0-21.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-setuptools-39.0.1-13.module+el8.4.0+403+9ae17a31', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-setuptools-wheel-39.0.1-13.module+el8.4.0+403+9ae17a31', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-six-1.11.0-6.module+el8.4.0+403+9ae17a31', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-test-2.7.18-11.module+el8.7.0+1062+663ba31c.rocky.0.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-test-2.7.18-11.module+el8.7.0+1062+663ba31c.rocky.0.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-tkinter-2.7.18-11.module+el8.7.0+1062+663ba31c.rocky.0.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-tkinter-2.7.18-11.module+el8.7.0+1062+663ba31c.rocky.0.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-tools-2.7.18-11.module+el8.7.0+1062+663ba31c.rocky.0.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-tools-2.7.18-11.module+el8.7.0+1062+663ba31c.rocky.0.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-urllib3-1.24.2-3.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-virtualenv-15.1.0-21.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-wheel-0.31.1-3.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python2-wheel-wheel-0.31.1-3.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python3-docutils-0.14-12.module+el8.4.0+597+ddf0ddea', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-sqlalchemy-1.3.2-2.module+el8.4.0+597+ddf0ddea', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-sqlalchemy-1.3.2-2.module+el8.4.0+597+ddf0ddea', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'PyYAML-debugsource-3.12-16.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'PyYAML-debugsource-3.12-16.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'scipy-debugsource-1.0.0-21.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'scipy-debugsource-1.0.0-21.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
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
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Cython-debugsource / PyYAML-debugsource / babel / numpy-debugsource / etc');
}
