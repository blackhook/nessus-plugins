#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-4982. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153970);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2021-34798",
    "CVE-2021-36160",
    "CVE-2021-39275",
    "CVE-2021-40438"
  );
  script_xref(name:"IAVA", value:"2021-A-0440-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/15");

  script_name(english:"Debian DSA-4982-1 : apache2 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-4982 advisory.

  - Malformed requests may cause the server to dereference a NULL pointer. This issue affects Apache HTTP
    Server 2.4.48 and earlier. (CVE-2021-34798)

  - A carefully crafted request uri-path can cause mod_proxy_uwsgi to read above the allocated memory and
    crash (DoS). This issue affects Apache HTTP Server versions 2.4.30 to 2.4.48 (inclusive). (CVE-2021-36160)

  - ap_escape_quotes() may write beyond the end of a buffer when given malicious input. No included modules
    pass untrusted data to these functions, but third-party / external modules may. This issue affects Apache
    HTTP Server 2.4.48 and earlier. (CVE-2021-39275)

  - A crafted request uri-path can cause mod_proxy to forward the request to an origin server choosen by the
    remote user. This issue affects Apache HTTP Server 2.4.48 and earlier. (CVE-2021-40438)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/apache2");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-4982");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-34798");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36160");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39275");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40438");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/apache2");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/apache2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the apache2 packages.

For the stable distribution (bullseye), these problems have been fixed in version 2.4.51-1~deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39275");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/10");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(10)\.[0-9]+|^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0 / 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'apache2', 'reference': '2.4.38-3+deb10u6'},
    {'release': '10.0', 'prefix': 'apache2-bin', 'reference': '2.4.38-3+deb10u6'},
    {'release': '10.0', 'prefix': 'apache2-data', 'reference': '2.4.38-3+deb10u6'},
    {'release': '10.0', 'prefix': 'apache2-dev', 'reference': '2.4.38-3+deb10u6'},
    {'release': '10.0', 'prefix': 'apache2-doc', 'reference': '2.4.38-3+deb10u6'},
    {'release': '10.0', 'prefix': 'apache2-ssl-dev', 'reference': '2.4.38-3+deb10u6'},
    {'release': '10.0', 'prefix': 'apache2-suexec-custom', 'reference': '2.4.38-3+deb10u6'},
    {'release': '10.0', 'prefix': 'apache2-suexec-pristine', 'reference': '2.4.38-3+deb10u6'},
    {'release': '10.0', 'prefix': 'apache2-utils', 'reference': '2.4.38-3+deb10u6'},
    {'release': '10.0', 'prefix': 'libapache2-mod-md', 'reference': '2.4.38-3+deb10u6'},
    {'release': '10.0', 'prefix': 'libapache2-mod-proxy-uwsgi', 'reference': '2.4.38-3+deb10u6'},
    {'release': '11.0', 'prefix': 'apache2', 'reference': '2.4.51-1~deb11u1'},
    {'release': '11.0', 'prefix': 'apache2-bin', 'reference': '2.4.51-1~deb11u1'},
    {'release': '11.0', 'prefix': 'apache2-data', 'reference': '2.4.51-1~deb11u1'},
    {'release': '11.0', 'prefix': 'apache2-dev', 'reference': '2.4.51-1~deb11u1'},
    {'release': '11.0', 'prefix': 'apache2-doc', 'reference': '2.4.51-1~deb11u1'},
    {'release': '11.0', 'prefix': 'apache2-ssl-dev', 'reference': '2.4.51-1~deb11u1'},
    {'release': '11.0', 'prefix': 'apache2-suexec-custom', 'reference': '2.4.51-1~deb11u1'},
    {'release': '11.0', 'prefix': 'apache2-suexec-pristine', 'reference': '2.4.51-1~deb11u1'},
    {'release': '11.0', 'prefix': 'apache2-utils', 'reference': '2.4.51-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libapache2-mod-md', 'reference': '2.4.51-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libapache2-mod-proxy-uwsgi', 'reference': '2.4.51-1~deb11u1'}
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
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache2 / apache2-bin / apache2-data / apache2-dev / apache2-doc / etc');
}
