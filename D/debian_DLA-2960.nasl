#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2960. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159141);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/13");

  script_cve_id(
    "CVE-2022-22719",
    "CVE-2022-22720",
    "CVE-2022-22721",
    "CVE-2022-23943"
  );
  script_xref(name:"IAVA", value:"2022-A-0124-S");

  script_name(english:"Debian DLA-2960-1 : apache2 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2960 advisory.

  - A carefully crafted request body can cause a read to a random memory area which could cause the process to
    crash. This issue affects Apache HTTP Server 2.4.52 and earlier. (CVE-2022-22719)

  - Apache HTTP Server 2.4.52 and earlier fails to close inbound connection when errors are encountered
    discarding the request body, exposing the server to HTTP Request Smuggling (CVE-2022-22720)

  - If LimitXMLRequestBody is set to allow request bodies larger than 350MB (defaults to 1M) on 32 bit systems
    an integer overflow happens which later causes out of bounds writes. This issue affects Apache HTTP Server
    2.4.52 and earlier. (CVE-2022-22721)

  - Out-of-bounds Write vulnerability in mod_sed of Apache HTTP Server allows an attacker to overwrite heap
    memory with possibly attacker provided data. This issue affects Apache HTTP Server 2.4 version 2.4.52 and
    prior versions. (CVE-2022-23943)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/apache2");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2960");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-22719");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-22720");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-22721");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23943");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/apache2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the apache2 packages.

For Debian 9 stretch, these problems have been fixed in version 2.4.25-3+deb9u13.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23943");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-ssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-suexec-custom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-suexec-pristine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '9.0', 'prefix': 'apache2', 'reference': '2.4.25-3+deb9u13'},
    {'release': '9.0', 'prefix': 'apache2-bin', 'reference': '2.4.25-3+deb9u13'},
    {'release': '9.0', 'prefix': 'apache2-data', 'reference': '2.4.25-3+deb9u13'},
    {'release': '9.0', 'prefix': 'apache2-dbg', 'reference': '2.4.25-3+deb9u13'},
    {'release': '9.0', 'prefix': 'apache2-dev', 'reference': '2.4.25-3+deb9u13'},
    {'release': '9.0', 'prefix': 'apache2-doc', 'reference': '2.4.25-3+deb9u13'},
    {'release': '9.0', 'prefix': 'apache2-ssl-dev', 'reference': '2.4.25-3+deb9u13'},
    {'release': '9.0', 'prefix': 'apache2-suexec-custom', 'reference': '2.4.25-3+deb9u13'},
    {'release': '9.0', 'prefix': 'apache2-suexec-pristine', 'reference': '2.4.25-3+deb9u13'},
    {'release': '9.0', 'prefix': 'apache2-utils', 'reference': '2.4.25-3+deb9u13'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache2 / apache2-bin / apache2-data / apache2-dbg / apache2-dev / etc');
}
