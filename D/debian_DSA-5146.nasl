#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5146. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(161493);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/24");

  script_cve_id("CVE-2021-41136", "CVE-2022-23634", "CVE-2022-24790");

  script_name(english:"Debian DSA-5146-1 : puma - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dsa-5146 advisory.

  - Puma is a HTTP 1.1 server for Ruby/Rack applications. Prior to versions 5.5.1 and 4.3.9, using `puma` with
    a proxy which forwards HTTP header values which contain the LF character could allow HTTP request
    smugggling. A client could smuggle a request through a proxy, causing the proxy to send a response back to
    another unknown client. The only proxy which has this behavior, as far as the Puma team is aware of, is
    Apache Traffic Server. If the proxy uses persistent connections and the client adds another request in via
    HTTP pipelining, the proxy may mistake it as the first request's body. Puma, however, would see it as two
    requests, and when processing the second request, send back a response that the proxy does not expect. If
    the proxy has reused the persistent connection to Puma to send another request for a different client, the
    second response from the first client will be sent to the second client. This vulnerability was patched in
    Puma 5.5.1 and 4.3.9. As a workaround, do not use Apache Traffic Server with `puma`. (CVE-2021-41136)

  - Puma is a Ruby/Rack web server built for parallelism. Prior to `puma` version `5.6.2`, `puma` may not
    always call `close` on the response body. Rails, prior to version `7.0.2.2`, depended on the response body
    being closed in order for its `CurrentAttributes` implementation to work correctly. The combination of
    these two behaviors (Puma not closing the body + Rails' Executor implementation) causes information
    leakage. This problem is fixed in Puma versions 5.6.2 and 4.3.11. This problem is fixed in Rails versions
    7.02.2, 6.1.4.6, 6.0.4.6, and 5.2.6.2. Upgrading to a patched Rails _or_ Puma version fixes the
    vulnerability. (CVE-2022-23634)

  - Puma is a simple, fast, multi-threaded, parallel HTTP 1.1 server for Ruby/Rack applications. When using
    Puma behind a proxy that does not properly validate that the incoming HTTP request matches the RFC7230
    standard, Puma and the frontend proxy may disagree on where a request starts and ends. This would allow
    requests to be smuggled via the front-end proxy to Puma. The vulnerability has been fixed in 5.6.4 and
    4.3.12. Users are advised to upgrade as soon as possible. Workaround: when deploying a proxy in front of
    Puma, turning on any and all functionality to make sure that the request matches the RFC7230 standard.
    (CVE-2022-24790)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/puma");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5146");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41136");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23634");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24790");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/puma");
  script_set_attribute(attribute:"solution", value:
"Upgrade the puma packages.

For the stable distribution (bullseye), this problem has been fixed in version 4.3.8-1+deb11u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24790");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:puma");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'puma', 'reference': '4.3.8-1+deb11u2'}
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
