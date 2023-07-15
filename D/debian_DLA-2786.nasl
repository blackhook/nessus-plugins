#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2786. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154195);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2018-1000168", "CVE-2020-11080");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Debian DLA-2786-1 : nghttp2 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2786 advisory.

  - nghttp2 version >= 1.10.0 and nghttp2 <= v1.31.0 contains an Improper Input Validation CWE-20
    vulnerability in ALTSVC frame handling that can result in segmentation fault leading to denial of service.
    This attack appears to be exploitable via network client. This vulnerability appears to have been fixed in
    >= 1.31.1. (CVE-2018-1000168)

  - In nghttp2 before version 1.41.0, the overly large HTTP/2 SETTINGS frame payload causes denial of service.
    The proof of concept attack involves a malicious client constructing a SETTINGS frame with a length of
    14,400 bytes (2400 individual settings entries) over and over again. The attack causes the CPU to spike at
    100%. nghttp2 v1.41.0 fixes this vulnerability. There is a workaround to this vulnerability. Implement
    nghttp2_on_frame_recv_callback callback, and if received frame is SETTINGS frame and the number of
    settings entries are large (e.g., > 32), then drop the connection. (CVE-2020-11080)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/nghttp2");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2786");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-1000168");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11080");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/nghttp2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the nghttp2 packages.

For Debian 9 stretch, these problems have been fixed in version 1.18.1-1+deb9u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11080");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnghttp2-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnghttp2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnghttp2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nghttp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nghttp2-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nghttp2-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nghttp2-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
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
    {'release': '9.0', 'prefix': 'libnghttp2-14', 'reference': '1.18.1-1+deb9u2'},
    {'release': '9.0', 'prefix': 'libnghttp2-dev', 'reference': '1.18.1-1+deb9u2'},
    {'release': '9.0', 'prefix': 'libnghttp2-doc', 'reference': '1.18.1-1+deb9u2'},
    {'release': '9.0', 'prefix': 'nghttp2', 'reference': '1.18.1-1+deb9u2'},
    {'release': '9.0', 'prefix': 'nghttp2-client', 'reference': '1.18.1-1+deb9u2'},
    {'release': '9.0', 'prefix': 'nghttp2-proxy', 'reference': '1.18.1-1+deb9u2'},
    {'release': '9.0', 'prefix': 'nghttp2-server', 'reference': '1.18.1-1+deb9u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnghttp2-14 / libnghttp2-dev / libnghttp2-doc / nghttp2 / etc');
}
