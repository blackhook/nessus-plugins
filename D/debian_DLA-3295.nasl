#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3295. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(170880);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/31");

  script_cve_id("CVE-2022-24785", "CVE-2022-31129");

  script_name(english:"Debian DLA-3295-1 : node-moment - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3295 advisory.

  - Moment.js is a JavaScript date library for parsing, validating, manipulating, and formatting dates. A path
    traversal vulnerability impacts npm (server) users of Moment.js between versions 1.0.1 and 2.29.1,
    especially if a user-provided locale string is directly used to switch moment locale. This problem is
    patched in 2.29.2, and the patch can be applied to all affected versions. As a workaround, sanitize the
    user-provided locale name before passing it to Moment.js. (CVE-2022-24785)

  - moment is a JavaScript date library for parsing, validating, manipulating, and formatting dates. Affected
    versions of moment were found to use an inefficient parsing algorithm. Specifically using string-to-date
    parsing in moment (more specifically rfc2822 parsing, which is tried by default) has quadratic (N^2)
    complexity on specific inputs. Users may notice a noticeable slowdown is observed with inputs above 10k
    characters. Users who pass user-provided strings without sanity length checks to moment constructor are
    vulnerable to (Re)DoS attacks. The problem is patched in 2.29.4, the patch can be applied to all affected
    versions with minimal tweaking. Users are advised to upgrade. Users unable to upgrade should consider
    limiting date lengths accepted from user input. (CVE-2022-31129)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1009327");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/node-moment");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3295");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24785");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31129");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/node-moment");
  script_set_attribute(attribute:"solution", value:
"Upgrade the node-moment packages.

For Debian 10 buster, these problems have been fixed in version 2.24.0+ds-1+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24785");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjs-moment");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-moment");
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
    {'release': '10.0', 'prefix': 'libjs-moment', 'reference': '2.24.0+ds-1+deb10u1'},
    {'release': '10.0', 'prefix': 'node-moment', 'reference': '2.24.0+ds-1+deb10u1'}
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
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libjs-moment / node-moment');
}
