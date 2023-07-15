#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3212. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(168233);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/28");

  script_cve_id("CVE-2022-39348");

  script_name(english:"Debian DLA-3212-1 : twisted - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3212
advisory.

  - Twisted is an event-based framework for internet applications. Started with version 0.9.4, when the host
    header does not match a configured host `twisted.web.vhost.NameVirtualHost` will return a `NoResource`
    resource which renders the Host header unescaped into the 404 response allowing HTML and script injection.
    In practice this should be very difficult to exploit as being able to modify the Host header of a normal
    HTTP request implies that one is already in a privileged position. This issue was fixed in version
    22.10.0rc1. There are no known workarounds. (CVE-2022-39348)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/twisted");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3212");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39348");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/twisted");
  script_set_attribute(attribute:"solution", value:
"Upgrade the twisted packages.

For Debian 10 buster, this problem has been fixed in version 18.9.0-3+deb10u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-39348");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-bin-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-conch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-names");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-news");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-runner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-runner-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-words");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-twisted");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-twisted-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-twisted-bin-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:twisted-doc");
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

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'python-twisted', 'reference': '18.9.0-3+deb10u2'},
    {'release': '10.0', 'prefix': 'python-twisted-bin', 'reference': '18.9.0-3+deb10u2'},
    {'release': '10.0', 'prefix': 'python-twisted-bin-dbg', 'reference': '18.9.0-3+deb10u2'},
    {'release': '10.0', 'prefix': 'python-twisted-conch', 'reference': '18.9.0-3+deb10u2'},
    {'release': '10.0', 'prefix': 'python-twisted-core', 'reference': '18.9.0-3+deb10u2'},
    {'release': '10.0', 'prefix': 'python-twisted-mail', 'reference': '18.9.0-3+deb10u2'},
    {'release': '10.0', 'prefix': 'python-twisted-names', 'reference': '18.9.0-3+deb10u2'},
    {'release': '10.0', 'prefix': 'python-twisted-news', 'reference': '18.9.0-3+deb10u2'},
    {'release': '10.0', 'prefix': 'python-twisted-runner', 'reference': '18.9.0-3+deb10u2'},
    {'release': '10.0', 'prefix': 'python-twisted-runner-dbg', 'reference': '18.9.0-3+deb10u2'},
    {'release': '10.0', 'prefix': 'python-twisted-web', 'reference': '18.9.0-3+deb10u2'},
    {'release': '10.0', 'prefix': 'python-twisted-words', 'reference': '18.9.0-3+deb10u2'},
    {'release': '10.0', 'prefix': 'python3-twisted', 'reference': '18.9.0-3+deb10u2'},
    {'release': '10.0', 'prefix': 'python3-twisted-bin', 'reference': '18.9.0-3+deb10u2'},
    {'release': '10.0', 'prefix': 'python3-twisted-bin-dbg', 'reference': '18.9.0-3+deb10u2'},
    {'release': '10.0', 'prefix': 'twisted-doc', 'reference': '18.9.0-3+deb10u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-twisted / python-twisted-bin / python-twisted-bin-dbg / etc');
}
