#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3456. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(177421);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/19");

  script_cve_id("CVE-2023-32681");

  script_name(english:"Debian DLA-3456-1 : requests - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has a package installed that is affected by a vulnerability as referenced in the dla-3456
advisory.

  - Requests is a HTTP library. Since Requests 2.3.0, Requests has been leaking Proxy-Authorization headers to
    destination servers when redirected to an HTTPS endpoint. This is a product of how we use
    `rebuild_proxies` to reattach the `Proxy-Authorization` header to requests. For HTTP connections sent
    through the tunnel, the proxy will identify the header in the request itself and remove it prior to
    forwarding to the destination server. However when sent over HTTPS, the `Proxy-Authorization` header must
    be sent in the CONNECT request as the proxy has no visibility into the tunneled request. This results in
    Requests forwarding proxy credentials to the destination server unintentionally, allowing a malicious
    actor to potentially exfiltrate sensitive information. This issue has been patched in version 2.31.0.
    (CVE-2023-32681)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1036693");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/requests");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3456");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-32681");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/requests");
  script_set_attribute(attribute:"solution", value:
"Upgrade the requests packages.

For Debian 10 buster, this problem has been fixed in version 2.21.0-1+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32681");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:requests");
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
    {'release': '10.0', 'prefix': 'python-requests', 'reference': '2.21.0-1+deb10u1'},
    {'release': '10.0', 'prefix': 'python3-requests', 'reference': '2.21.0-1+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-requests / python3-requests');
}
