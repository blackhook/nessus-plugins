#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3436. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(176457);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/29");

  script_cve_id(
    "CVE-2018-16838",
    "CVE-2019-3811",
    "CVE-2021-3621",
    "CVE-2022-4254"
  );

  script_name(english:"Debian DLA-3436-1 : sssd - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3436 advisory.

  - A flaw was found in sssd Group Policy Objects implementation. When the GPO is not readable by SSSD due to
    a too strict permission settings on the server side, SSSD will allow all authenticated users to login
    instead of denying access. (CVE-2018-16838)

  - A vulnerability was found in sssd. If a user was configured with no home directory set, sssd would return
    '/' (the root directory) instead of '' (the empty string / no home directory). This could impact services
    that restrict the user's filesystem access to within their home directory through chroot() etc. All
    versions before 2.1 are vulnerable. (CVE-2019-3811)

  - A flaw was found in SSSD, where the sssctl command was vulnerable to shell command injection via the logs-
    fetch and cache-expire subcommands. This flaw allows an attacker to trick the root user into running a
    specially crafted sssctl command, such as via sudo, to gain root access. The highest threat from this
    vulnerability is to confidentiality, integrity, as well as system availability. (CVE-2021-3621)

  - sssd: libsss_certmap fails to sanitise certificate data used in LDAP filters (CVE-2022-4254)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=919051");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/sssd");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3436");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-16838");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-3811");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3621");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-4254");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/sssd");
  script_set_attribute(attribute:"solution", value:
"Upgrade the sssd packages.

For Debian 10 buster, these problems have been fixed in version 1.16.3-3.2+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3621");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-4254");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libipa-hbac-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libipa-hbac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-certmap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-certmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-idmap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-nss-idmap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-nss-idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-simpleifp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-simpleifp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsss-sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwbclient-sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwbclient-sssd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-libipa-hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-libsss-nss-idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-libipa-hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-libsss-nss-idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-ad-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-kcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sssd-tools");
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
    {'release': '10.0', 'prefix': 'libipa-hbac-dev', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'libipa-hbac0', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'libnss-sss', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'libpam-sss', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'libsss-certmap-dev', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'libsss-certmap0', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'libsss-idmap-dev', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'libsss-idmap0', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'libsss-nss-idmap-dev', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'libsss-nss-idmap0', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'libsss-simpleifp-dev', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'libsss-simpleifp0', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'libsss-sudo', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'libwbclient-sssd', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'libwbclient-sssd-dev', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'python-libipa-hbac', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'python-libsss-nss-idmap', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'python-sss', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'python3-libipa-hbac', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'python3-libsss-nss-idmap', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'python3-sss', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'sssd', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'sssd-ad', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'sssd-ad-common', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'sssd-common', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'sssd-dbus', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'sssd-ipa', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'sssd-kcm', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'sssd-krb5', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'sssd-krb5-common', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'sssd-ldap', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'sssd-proxy', 'reference': '1.16.3-3.2+deb10u1'},
    {'release': '10.0', 'prefix': 'sssd-tools', 'reference': '1.16.3-3.2+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libipa-hbac-dev / libipa-hbac0 / libnss-sss / libpam-sss / etc');
}
