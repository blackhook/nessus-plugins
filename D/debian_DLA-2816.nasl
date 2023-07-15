#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2816. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155060);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/11");

  script_cve_id("CVE-2021-32739", "CVE-2021-32743", "CVE-2021-37698");

  script_name(english:"Debian DLA-2816-1 : icinga2 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2816 advisory.

  - Icinga is a monitoring system which checks the availability of network resources, notifies users of
    outages, and generates performance data for reporting. From version 2.4.0 through version 2.12.4, a
    vulnerability exists that may allow privilege escalation for authenticated API users. With a read-ony
    user's credentials, an attacker can view most attributes of all config objects including `ticket_salt` of
    `ApiListener`. This salt is enough to compute a ticket for every possible common name (CN). A ticket, the
    master node's certificate, and a self-signed certificate are enough to successfully request the desired
    certificate from Icinga. That certificate may in turn be used to steal an endpoint or API user's identity.
    Versions 2.12.5 and 2.11.10 both contain a fix the vulnerability. As a workaround, one may either specify
    queryable types explicitly or filter out ApiListener objects. (CVE-2021-32739)

  - Icinga is a monitoring system which checks the availability of network resources, notifies users of
    outages, and generates performance data for reporting. In versions prior to 2.11.10 and from version
    2.12.0 through version 2.12.4, some of the Icinga 2 features that require credentials for external
    services expose those credentials through the API to authenticated API users with read permissions for the
    corresponding object types. IdoMysqlConnection and IdoPgsqlConnection (every released version) exposes the
    password of the user used to connect to the database. IcingaDB (added in 2.12.0) exposes the password used
    to connect to the Redis server. ElasticsearchWriter (added in 2.8.0)exposes the password used to connect
    to the Elasticsearch server. An attacker who obtains these credentials can impersonate Icinga to these
    services and add, modify and delete information there. If credentials with more permissions are in use,
    this increases the impact accordingly. Starting with the 2.11.10 and 2.12.5 releases, these passwords are
    no longer exposed via the API. As a workaround, API user permissions can be restricted to not allow
    querying of any affected objects, either by explicitly listing only the required object types for object
    query permissions, or by applying a filter rule. (CVE-2021-32743)

  - Icinga is a monitoring system which checks the availability of network resources, notifies users of
    outages, and generates performance data for reporting. In versions 2.5.0 through 2.13.0,
    ElasticsearchWriter, GelfWriter, InfluxdbWriter and Influxdb2Writer do not verify the server's certificate
    despite a certificate authority being specified. Icinga 2 instances which connect to any of the mentioned
    time series databases (TSDBs) using TLS over a spoofable infrastructure should immediately upgrade to
    version 2.13.1, 2.12.6, or 2.11.11 to patch the issue. Such instances should also change the credentials
    (if any) used by the TSDB writer feature to authenticate against the TSDB. There are no workarounds aside
    from upgrading. (CVE-2021-37698)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=991494");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/icinga2");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2816");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32739");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32743");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37698");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/icinga2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the icinga2 packages.

For Debian 9 stretch, these problems have been fixed in version 2.6.0-2+deb9u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32743");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icinga2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icinga2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icinga2-classicui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icinga2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icinga2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icinga2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icinga2-ido-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icinga2-ido-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icinga2-studio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libicinga2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-icinga2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
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

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'icinga2', 'reference': '2.6.0-2+deb9u2'},
    {'release': '9.0', 'prefix': 'icinga2-bin', 'reference': '2.6.0-2+deb9u2'},
    {'release': '9.0', 'prefix': 'icinga2-classicui', 'reference': '2.6.0-2+deb9u2'},
    {'release': '9.0', 'prefix': 'icinga2-common', 'reference': '2.6.0-2+deb9u2'},
    {'release': '9.0', 'prefix': 'icinga2-dbg', 'reference': '2.6.0-2+deb9u2'},
    {'release': '9.0', 'prefix': 'icinga2-doc', 'reference': '2.6.0-2+deb9u2'},
    {'release': '9.0', 'prefix': 'icinga2-ido-mysql', 'reference': '2.6.0-2+deb9u2'},
    {'release': '9.0', 'prefix': 'icinga2-ido-pgsql', 'reference': '2.6.0-2+deb9u2'},
    {'release': '9.0', 'prefix': 'icinga2-studio', 'reference': '2.6.0-2+deb9u2'},
    {'release': '9.0', 'prefix': 'libicinga2', 'reference': '2.6.0-2+deb9u2'},
    {'release': '9.0', 'prefix': 'vim-icinga2', 'reference': '2.6.0-2+deb9u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'icinga2 / icinga2-bin / icinga2-classicui / icinga2-common / etc');
}
