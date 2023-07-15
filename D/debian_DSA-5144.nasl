#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5144. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(161436);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/23");

  script_cve_id("CVE-2019-18823", "CVE-2022-26110");

  script_name(english:"Debian DSA-5144-1 : condor - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5144 advisory.

  - HTCondor up to and including stable series 8.8.6 and development series 8.9.4 has Incorrect Access
    Control. It is possible to use a different authentication method to submit a job than the administrator
    has specified. If the administrator has configured the READ or WRITE methods to include CLAIMTOBE, then it
    is possible to impersonate another user to the condor_schedd. (For example to submit or remove jobs)
    (CVE-2019-18823)

  - An issue was discovered in HTCondor 8.8.x before 8.8.16, 9.0.x before 9.0.10, and 9.1.x before 9.6.0. When
    a user authenticates to an HTCondor daemon via the CLAIMTOBE method, the user can then impersonate any
    entity when issuing additional commands to that daemon. (CVE-2022-26110)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=963777");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/condor");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5144");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-18823");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26110");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/condor");
  script_set_attribute(attribute:"solution", value:
"Upgrade the condor packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18823");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:htcondor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:htcondor-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:htcondor-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:htcondor-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libclassad-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libclassad8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'htcondor', 'reference': '8.6.8~dfsg.1-2+deb10u1'},
    {'release': '10.0', 'prefix': 'htcondor-dbg', 'reference': '8.6.8~dfsg.1-2+deb10u1'},
    {'release': '10.0', 'prefix': 'htcondor-dev', 'reference': '8.6.8~dfsg.1-2+deb10u1'},
    {'release': '10.0', 'prefix': 'htcondor-doc', 'reference': '8.6.8~dfsg.1-2+deb10u1'},
    {'release': '10.0', 'prefix': 'libclassad-dev', 'reference': '8.6.8~dfsg.1-2+deb10u1'},
    {'release': '10.0', 'prefix': 'libclassad8', 'reference': '8.6.8~dfsg.1-2+deb10u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'htcondor / htcondor-dbg / htcondor-dev / htcondor-doc / libclassad-dev / etc');
}
