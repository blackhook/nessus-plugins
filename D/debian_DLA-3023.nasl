#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3023. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(161515);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/26");

  script_cve_id("CVE-2019-16770", "CVE-2020-5247", "CVE-2022-23634");

  script_name(english:"Debian DLA-3023-1 : puma - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-3023 advisory.

  - In Puma before versions 3.12.2 and 4.3.1, a poorly-behaved client could use keepalive requests to
    monopolize Puma's reactor and create a denial of service attack. If more keepalive connections to Puma are
    opened than there are threads available, additional connections will wait permanently if the attacker
    sends requests frequently enough. This vulnerability is patched in Puma 4.3.1 and 3.12.2. (CVE-2019-16770)

  - In Puma (RubyGem) before 4.3.2 and before 3.12.3, if an application using Puma allows untrusted input in a
    response header, an attacker can use newline characters (i.e. `CR`, `LF` or`/r`, `/n`) to end the header
    and inject malicious content, such as additional headers or an entirely new response body. This
    vulnerability is known as HTTP Response Splitting. While not an attack in itself, response splitting is a
    vector for several other attacks, such as cross-site scripting (XSS). This is related to CVE-2019-16254,
    which fixed this vulnerability for the WEBrick Ruby web server. This has been fixed in versions 4.3.2 and
    3.12.3 by checking all headers for line endings and rejecting headers with those characters.
    (CVE-2020-5247)

  - Puma is a Ruby/Rack web server built for parallelism. Prior to `puma` version `5.6.2`, `puma` may not
    always call `close` on the response body. Rails, prior to version `7.0.2.2`, depended on the response body
    being closed in order for its `CurrentAttributes` implementation to work correctly. The combination of
    these two behaviors (Puma not closing the body + Rails' Executor implementation) causes information
    leakage. This problem is fixed in Puma versions 5.6.2 and 4.3.11. This problem is fixed in Rails versions
    7.02.2, 6.1.4.6, 6.0.4.6, and 5.2.6.2. Upgrading to a patched Rails _or_ Puma version fixes the
    vulnerability. (CVE-2022-23634)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=946312");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/puma");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3023");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-16770");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-5247");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23634");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/puma");
  script_set_attribute(attribute:"solution", value:
"Upgrade the puma packages.

For Debian 9 stretch, these problems have been fixed in version 3.6.0-1+deb9u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5247");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:puma");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
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
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'puma', 'reference': '3.6.0-1+deb9u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'puma');
}
