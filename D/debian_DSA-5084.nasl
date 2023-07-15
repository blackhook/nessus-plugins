#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5084. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158204);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2022-22589",
    "CVE-2022-22590",
    "CVE-2022-22592",
    "CVE-2022-22620"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/02/25");

  script_name(english:"Debian DSA-5084-1 : wpewebkit - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5084 advisory.

  - A use after free issue was addressed with improved memory management. This issue is fixed in macOS
    Monterey 12.2.1, iOS 15.3.1 and iPadOS 15.3.1, Safari 15.3 (v. 16612.4.9.1.8 and 15612.4.9.1.8).
    Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a
    report that this issue may have been actively exploited.. (CVE-2022-22620)

  - A validation issue was addressed with improved input sanitization. This issue is fixed in iOS 15.3 and
    iPadOS 15.3, watchOS 8.4, tvOS 15.3, Safari 15.3, macOS Monterey 12.2. Processing a maliciously crafted
    mail message may lead to running arbitrary javascript. (CVE-2022-22589)

  - A use after free issue was addressed with improved memory management. This issue is fixed in iOS 15.3 and
    iPadOS 15.3, watchOS 8.4, tvOS 15.3, Safari 15.3, macOS Monterey 12.2. Processing maliciously crafted web
    content may lead to arbitrary code execution. (CVE-2022-22590)

  - A logic issue was addressed with improved state management. This issue is fixed in iOS 15.3 and iPadOS
    15.3, watchOS 8.4, tvOS 15.3, Safari 15.3, macOS Monterey 12.2. Processing maliciously crafted web content
    may prevent Content Security Policy from being enforced. (CVE-2022-22592)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/wpewebkit");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5084");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-22589");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-22590");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-22592");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-22620");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/wpewebkit");
  script_set_attribute(attribute:"solution", value:
"Upgrade the wpewebkit packages.

For the stable distribution (bullseye), these problems have been fixed in version 2.34.6-1~deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22620");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwpewebkit-1.0-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwpewebkit-1.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwpewebkit-1.0-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wpewebkit-driver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'libwpewebkit-1.0-3', 'reference': '2.34.6-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libwpewebkit-1.0-dev', 'reference': '2.34.6-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libwpewebkit-1.0-doc', 'reference': '2.34.6-1~deb11u1'},
    {'release': '11.0', 'prefix': 'wpewebkit-driver', 'reference': '2.34.6-1~deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libwpewebkit-1.0-3 / libwpewebkit-1.0-dev / libwpewebkit-1.0-doc / etc');
}
