#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3093. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(164961);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/13");

  script_cve_id(
    "CVE-2022-21831",
    "CVE-2022-22577",
    "CVE-2022-23633",
    "CVE-2022-27777",
    "CVE-2022-32224"
  );

  script_name(english:"Debian DLA-3093-1 : rails - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3093 advisory.

  - A code injection vulnerability exists in the Active Storage >= v5.2.0 that could allow an attacker to
    execute code via image_processing arguments. (CVE-2022-21831)

  - An XSS Vulnerability in Action Pack >= 5.2.0 and < 5.2.0 that could allow an attacker to bypass CSP for
    non HTML like responses. (CVE-2022-22577)

  - Action Pack is a framework for handling and responding to web requests. Under certain circumstances
    response bodies will not be closed. In the event a response is *not* notified of a `close`,
    `ActionDispatch::Executor` will not know to reset thread local state for the next request. This can lead
    to data being leaked to subsequent requests.This has been fixed in Rails 7.0.2.1, 6.1.4.5, 6.0.4.5, and
    5.2.6.1. Upgrading is highly recommended, but to work around this problem a middleware described in GHSA-
    wh98-p28r-vrc9 can be used. (CVE-2022-23633)

  - A XSS Vulnerability in Action View tag helpers >= 5.2.0 and < 5.2.0 which would allow an attacker to
    inject content if able to control input into specific attributes. (CVE-2022-27777)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/rails");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3093");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21831");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-22577");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23633");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27777");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/rails");
  script_set_attribute(attribute:"solution", value:
"Upgrade the rails packages.

For Debian 10 buster, these problems have been fixed in version 2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21831");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-actioncable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-actionmailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-actionview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-activejob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-activemodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-activestorage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-activesupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-railties");
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
    {'release': '10.0', 'prefix': 'rails', 'reference': '2:5.2.2.1+dfsg-1+deb10u4'},
    {'release': '10.0', 'prefix': 'ruby-actioncable', 'reference': '2:5.2.2.1+dfsg-1+deb10u4'},
    {'release': '10.0', 'prefix': 'ruby-actionmailer', 'reference': '2:5.2.2.1+dfsg-1+deb10u4'},
    {'release': '10.0', 'prefix': 'ruby-actionpack', 'reference': '2:5.2.2.1+dfsg-1+deb10u4'},
    {'release': '10.0', 'prefix': 'ruby-actionview', 'reference': '2:5.2.2.1+dfsg-1+deb10u4'},
    {'release': '10.0', 'prefix': 'ruby-activejob', 'reference': '2:5.2.2.1+dfsg-1+deb10u4'},
    {'release': '10.0', 'prefix': 'ruby-activemodel', 'reference': '2:5.2.2.1+dfsg-1+deb10u4'},
    {'release': '10.0', 'prefix': 'ruby-activerecord', 'reference': '2:5.2.2.1+dfsg-1+deb10u4'},
    {'release': '10.0', 'prefix': 'ruby-activestorage', 'reference': '2:5.2.2.1+dfsg-1+deb10u4'},
    {'release': '10.0', 'prefix': 'ruby-activesupport', 'reference': '2:5.2.2.1+dfsg-1+deb10u4'},
    {'release': '10.0', 'prefix': 'ruby-rails', 'reference': '2:5.2.2.1+dfsg-1+deb10u4'},
    {'release': '10.0', 'prefix': 'ruby-railties', 'reference': '2:5.2.2.1+dfsg-1+deb10u4'}
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
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rails / ruby-actioncable / ruby-actionmailer / ruby-actionpack / etc');
}
