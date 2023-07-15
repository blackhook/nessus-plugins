#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-4937. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151485);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id(
    "CVE-2020-35452",
    "CVE-2021-26690",
    "CVE-2021-26691",
    "CVE-2021-30641",
    "CVE-2021-31618"
  );
  script_xref(name:"IAVA", value:"2021-A-0259-S");

  script_name(english:"Debian DSA-4937-1 : apache2 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-4937 advisory.

  - Apache HTTP Server versions 2.4.0 to 2.4.46 A specially crafted Digest nonce can cause a stack overflow in
    mod_auth_digest. There is no report of this overflow being exploitable, nor the Apache HTTP Server team
    could create one, though some particular compiler and/or compilation option might make it possible, with
    limited consequences anyway due to the size (a single byte) and the value (zero byte) of the overflow
    (CVE-2020-35452)

  - Apache HTTP Server versions 2.4.0 to 2.4.46 A specially crafted Cookie header handled by mod_session can
    cause a NULL pointer dereference and crash, leading to a possible Denial Of Service (CVE-2021-26690)

  - In Apache HTTP Server versions 2.4.0 to 2.4.46 a specially crafted SessionHeader sent by an origin server
    could cause a heap overflow (CVE-2021-26691)

  - Apache HTTP Server versions 2.4.39 to 2.4.46 Unexpected matching behavior with 'MergeSlashes OFF'
    (CVE-2021-30641)

  - Apache HTTP Server protocol handler for the HTTP/2 protocol checks received request headers against the
    size limitations as configured for the server and used for the HTTP/1 protocol as well. On violation of
    these restrictions and HTTP response is sent to the client with a status code indicating why the request
    was rejected. This rejection response was not fully initialised in the HTTP/2 protocol handler if the
    offending header was the very first one received or appeared in a a footer. This led to a NULL pointer
    dereference on initialised memory, crashing reliably the child process. Since such a triggering HTTP/2
    request is easy to craft and submit, this can be exploited to DoS the server. This issue affected
    mod_http2 1.15.17 and Apache HTTP Server version 2.4.47 only. Apache HTTP Server 2.4.47 was never
    released. (CVE-2021-31618)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/apache2");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-4937");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-35452");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-26690");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-26691");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-30641");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-31618");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/apache2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the apache2 packages.

For the stable distribution (buster), these problems have been fixed in version 2.4.38-3+deb10u5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26691");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-ssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-suexec-custom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-suexec-pristine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-md");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-proxy-uwsgi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + release);
cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

pkgs = [
    {'release': '10.0', 'prefix': 'apache2', 'reference': '2.4.38-3+deb10u5'},
    {'release': '10.0', 'prefix': 'apache2-bin', 'reference': '2.4.38-3+deb10u5'},
    {'release': '10.0', 'prefix': 'apache2-data', 'reference': '2.4.38-3+deb10u5'},
    {'release': '10.0', 'prefix': 'apache2-dev', 'reference': '2.4.38-3+deb10u5'},
    {'release': '10.0', 'prefix': 'apache2-doc', 'reference': '2.4.38-3+deb10u5'},
    {'release': '10.0', 'prefix': 'apache2-ssl-dev', 'reference': '2.4.38-3+deb10u5'},
    {'release': '10.0', 'prefix': 'apache2-suexec-custom', 'reference': '2.4.38-3+deb10u5'},
    {'release': '10.0', 'prefix': 'apache2-suexec-pristine', 'reference': '2.4.38-3+deb10u5'},
    {'release': '10.0', 'prefix': 'apache2-utils', 'reference': '2.4.38-3+deb10u5'},
    {'release': '10.0', 'prefix': 'libapache2-mod-md', 'reference': '2.4.38-3+deb10u5'},
    {'release': '10.0', 'prefix': 'libapache2-mod-proxy-uwsgi', 'reference': '2.4.38-3+deb10u5'}
];

flag = 0;
foreach package_array ( pkgs ) {
  release = NULL;
  prefix = NULL;
  reference = NULL;
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
  tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache2 / apache2-bin / apache2-data / apache2-dev / apache2-doc / etc');
}
