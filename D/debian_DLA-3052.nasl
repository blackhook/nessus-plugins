#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3052. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(162402);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/20");

  script_cve_id("CVE-2019-18928", "CVE-2021-33582");

  script_name(english:"Debian DLA-3052-1 : cyrus-imapd - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3052 advisory.

  - Cyrus IMAP 2.5.x before 2.5.14 and 3.x before 3.0.12 allows privilege escalation because an HTTP request
    may be interpreted in the authentication context of an unrelated previous request that arrived over the
    same connection. (CVE-2019-18928)

  - Cyrus IMAP before 3.4.2 allows remote attackers to cause a denial of service (multiple-minute daemon hang)
    via input that is mishandled during hash-table interaction. Because there are many insertions into a
    single bucket, strcmp becomes slow. This is fixed in 3.4.2, 3.2.8, and 3.0.16. (CVE-2021-33582)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=993433");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/cyrus-imapd");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3052");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-18928");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33582");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/cyrus-imapd");
  script_set_attribute(attribute:"solution", value:
"Upgrade the cyrus-imapd packages.

For Debian 9 stretch, these problems have been fixed in version 2.5.10-3+deb9u3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18928");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-caldav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-imapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-murder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-nntpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-pop3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-replication");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcyrus-imap-perl");
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
    {'release': '9.0', 'prefix': 'cyrus-admin', 'reference': '2.5.10-3+deb9u3'},
    {'release': '9.0', 'prefix': 'cyrus-caldav', 'reference': '2.5.10-3+deb9u3'},
    {'release': '9.0', 'prefix': 'cyrus-clients', 'reference': '2.5.10-3+deb9u3'},
    {'release': '9.0', 'prefix': 'cyrus-common', 'reference': '2.5.10-3+deb9u3'},
    {'release': '9.0', 'prefix': 'cyrus-dev', 'reference': '2.5.10-3+deb9u3'},
    {'release': '9.0', 'prefix': 'cyrus-doc', 'reference': '2.5.10-3+deb9u3'},
    {'release': '9.0', 'prefix': 'cyrus-imapd', 'reference': '2.5.10-3+deb9u3'},
    {'release': '9.0', 'prefix': 'cyrus-murder', 'reference': '2.5.10-3+deb9u3'},
    {'release': '9.0', 'prefix': 'cyrus-nntpd', 'reference': '2.5.10-3+deb9u3'},
    {'release': '9.0', 'prefix': 'cyrus-pop3d', 'reference': '2.5.10-3+deb9u3'},
    {'release': '9.0', 'prefix': 'cyrus-replication', 'reference': '2.5.10-3+deb9u3'},
    {'release': '9.0', 'prefix': 'libcyrus-imap-perl', 'reference': '2.5.10-3+deb9u3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cyrus-admin / cyrus-caldav / cyrus-clients / cyrus-common / cyrus-dev / etc');
}
