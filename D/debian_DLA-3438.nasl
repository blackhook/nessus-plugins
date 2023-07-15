#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3438. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(176485);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/30");

  script_cve_id("CVE-2020-27507");

  script_name(english:"Debian DLA-3438-1 : kamailio - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3438
advisory.

  - The Kamailio SIP before 5.5.0 server mishandles INVITE requests with duplicated fields and overlength tag,
    leading to a buffer overflow that crashes the server or possibly have unspecified other impact.
    (CVE-2020-27507)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3438");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27507");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/kamailio");
  script_set_attribute(attribute:"solution", value:
"Upgrade the kamailio packages.

For Debian 10 Buster, this problem has been fixed in version 5.2.1-1+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27507");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-autheph-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-berkeley-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-berkeley-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-cnxcc-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-cpl-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-erlang-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-extra-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-geoip-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-geoip2-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-ims-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-json-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-kazoo-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-ldap-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-lua-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-memcached-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-mongodb-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-mono-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-mysql-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-outbound-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-perl-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-phonenum-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-postgres-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-presence-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-python-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-python3-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-rabbitmq-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-radius-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-redis-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-ruby-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-sctp-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-snmpstats-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-sqlite-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-systemd-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-tls-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-unixodbc-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-utils-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-websocket-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-xml-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio-xmpp-modules");
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
    {'release': '10.0', 'prefix': 'kamailio', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-autheph-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-berkeley-bin', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-berkeley-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-cnxcc-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-cpl-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-erlang-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-extra-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-geoip-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-geoip2-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-ims-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-json-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-kazoo-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-ldap-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-lua-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-memcached-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-mongodb-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-mono-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-mysql-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-outbound-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-perl-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-phonenum-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-postgres-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-presence-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-python-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-python3-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-rabbitmq-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-radius-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-redis-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-ruby-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-sctp-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-snmpstats-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-sqlite-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-systemd-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-tls-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-unixodbc-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-utils-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-websocket-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-xml-modules', 'reference': '5.2.1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kamailio-xmpp-modules', 'reference': '5.2.1-1+deb10u1'}
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
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kamailio / kamailio-autheph-modules / kamailio-berkeley-bin / etc');
}
