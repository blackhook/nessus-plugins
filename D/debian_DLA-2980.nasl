#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2980. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159663);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/12");

  script_cve_id("CVE-2022-24349", "CVE-2022-24917", "CVE-2022-24919");

  script_name(english:"Debian DLA-2980-1 : zabbix - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2980 advisory.

  - An authenticated user can create a link with reflected XSS payload for actions' pages, and send it to
    other users. Malicious code has access to all the same objects as the rest of the web page and can make
    arbitrary modifications to the contents of the page being displayed to a victim. This attack can be
    implemented with the help of social engineering and expiration of a number of factors - an attacker should
    have authorized access to the Zabbix Frontend and allowed network connection between a malicious server
    and victim's computer, understand attacked infrastructure, be recognized by the victim as a trustee and
    use trusted communication channel. (CVE-2022-24349)

  - An authenticated user can create a link with reflected Javascript code inside it for services' page and
    send it to other users. The payload can be executed only with a known CSRF token value of the victim,
    which is changed periodically and is difficult to predict. Malicious code has access to all the same
    objects as the rest of the web page and can make arbitrary modifications to the contents of the page being
    displayed to a victim during social engineering attacks. (CVE-2022-24917)

  - An authenticated user can create a link with reflected Javascript code inside it for graphs' page and send
    it to other users. The payload can be executed only with a known CSRF token value of the victim, which is
    changed periodically and is difficult to predict. Malicious code has access to all the same objects as the
    rest of the web page and can make arbitrary modifications to the contents of the page being displayed to a
    victim during social engineering attacks. (CVE-2022-24919)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/zabbix");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2980");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24349");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24917");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24919");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/zabbix");
  script_set_attribute(attribute:"solution", value:
"Upgrade the zabbix packages.

For Debian 9 stretch, these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24919");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-frontend-php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-java-gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-proxy-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-proxy-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-proxy-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-server-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-server-pgsql");
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
    {'release': '9.0', 'prefix': 'zabbix-agent', 'reference': '1:3.0.32+dfsg-0+deb9u3'},
    {'release': '9.0', 'prefix': 'zabbix-frontend-php', 'reference': '1:3.0.32+dfsg-0+deb9u3'},
    {'release': '9.0', 'prefix': 'zabbix-java-gateway', 'reference': '1:3.0.32+dfsg-0+deb9u3'},
    {'release': '9.0', 'prefix': 'zabbix-proxy-mysql', 'reference': '1:3.0.32+dfsg-0+deb9u3'},
    {'release': '9.0', 'prefix': 'zabbix-proxy-pgsql', 'reference': '1:3.0.32+dfsg-0+deb9u3'},
    {'release': '9.0', 'prefix': 'zabbix-proxy-sqlite3', 'reference': '1:3.0.32+dfsg-0+deb9u3'},
    {'release': '9.0', 'prefix': 'zabbix-server-mysql', 'reference': '1:3.0.32+dfsg-0+deb9u3'},
    {'release': '9.0', 'prefix': 'zabbix-server-pgsql', 'reference': '1:3.0.32+dfsg-0+deb9u3'}
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
    severity   : SECURITY_NOTE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'zabbix-agent / zabbix-frontend-php / zabbix-java-gateway / etc');
}
