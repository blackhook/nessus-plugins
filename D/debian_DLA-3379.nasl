#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3379. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(173778);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/02");

  script_cve_id(
    "CVE-2022-21216",
    "CVE-2022-21233",
    "CVE-2022-33196",
    "CVE-2022-33972",
    "CVE-2022-38090"
  );

  script_name(english:"Debian DLA-3379-1 : intel-microcode - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-3379 advisory.

  - Insufficient granularity of access control in out-of-band management in some Intel(R) Atom and Intel Xeon
    Scalable Processors may allow a privileged user to potentially enable escalation of privilege via adjacent
    network access. (CVE-2022-21216)

  - Improper isolation of shared resources in some Intel(R) Processors may allow a privileged user to
    potentially enable information disclosure via local access. (CVE-2022-21233)

  - Incorrect default permissions in some memory controller configurations for some Intel(R) Xeon(R)
    Processors when using Intel(R) Software Guard Extensions which may allow a privileged user to potentially
    enable escalation of privilege via local access. (CVE-2022-33196)

  - Incorrect calculation in microcode keying mechanism for some 3rd Generation Intel(R) Xeon(R) Scalable
    Processors may allow a privileged user to potentially enable information disclosure via local access.
    (CVE-2022-33972)

  - Improper isolation of shared resources in some Intel(R) Processors when using Intel(R) Software Guard
    Extensions may allow a privileged user to potentially enable information disclosure via local access.
    (CVE-2022-38090)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1031334");
  # https://security-tracker.debian.org/tracker/source-package/intel-microcode
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?019586d4");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3379");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21216");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21233");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-33196");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-33972");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-38090");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/intel-microcode");
  script_set_attribute(attribute:"solution", value:
"Upgrade the intel-microcode packages.

For Debian 10 buster, these problems have been fixed in version 3.20230214.1~deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21216");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:intel-microcode");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'intel-microcode', 'reference': '3.20230214.1~deb10u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'intel-microcode');
}
