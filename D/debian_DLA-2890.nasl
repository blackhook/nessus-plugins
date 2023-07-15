#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2890. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156920);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/27");

  script_cve_id("CVE-2021-33912", "CVE-2021-33913");

  script_name(english:"Debian DLA-2890-1 : libspf2 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2890 advisory.

  - libspf2 before 1.2.11 has a four-byte heap-based buffer overflow that might allow remote attackers to
    execute arbitrary code (via an unauthenticated e-mail message from anywhere on the Internet) with a
    crafted SPF DNS record, because of incorrect sprintf usage in SPF_record_expand_data in spf_expand.c. The
    vulnerable code may be part of the supply chain of a site's e-mail infrastructure (e.g., with additional
    configuration, Exim can use libspf2; the Postfix web site links to unofficial patches for use of libspf2
    with Postfix; older versions of spfquery relied on libspf2) but most often is not. (CVE-2021-33912)

  - libspf2 before 1.2.11 has a heap-based buffer overflow that might allow remote attackers to execute
    arbitrary code (via an unauthenticated e-mail message from anywhere on the Internet) with a crafted SPF
    DNS record, because of SPF_record_expand_data in spf_expand.c. The amount of overflowed data depends on
    the relationship between the length of an entire domain name and the length of its leftmost label. The
    vulnerable code may be part of the supply chain of a site's e-mail infrastructure (e.g., with additional
    configuration, Exim can use libspf2; the Postfix web site links to unofficial patches for use of libspf2
    with Postfix; older versions of spfquery relied on libspf2) but most often is not. (CVE-2021-33913)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libspf2");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2890");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33912");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33913");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/libspf2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libspf2 packages.

For Debian 9 stretch, these problems have been fixed in version 1.2.10-7+deb9u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33913");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmail-spf-xs-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspf2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspf2-2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspf2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:spfquery");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
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
    {'release': '9.0', 'prefix': 'libmail-spf-xs-perl', 'reference': '1.2.10-7+deb9u2'},
    {'release': '9.0', 'prefix': 'libspf2-2', 'reference': '1.2.10-7+deb9u2'},
    {'release': '9.0', 'prefix': 'libspf2-2-dbg', 'reference': '1.2.10-7+deb9u2'},
    {'release': '9.0', 'prefix': 'libspf2-dev', 'reference': '1.2.10-7+deb9u2'},
    {'release': '9.0', 'prefix': 'spfquery', 'reference': '1.2.10-7+deb9u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libmail-spf-xs-perl / libspf2-2 / libspf2-2-dbg / libspf2-dev / etc');
}
