##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5509-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162993);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2022-30550");
  script_xref(name:"USN", value:"5509-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS : Dovecot vulnerability (USN-5509-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS host has packages installed that are affected by a
vulnerability as referenced in the USN-5509-1 advisory.

  - An issue was discovered in the auth component in Dovecot 2.2 and 2.3 before 2.3.20. When two passdb
    configuration entries exist with the same driver and args settings, incorrect username_filter and
    mechanism settings can be applied to passdb definitions. These incorrectly applied settings can lead to an
    unintended security configuration and can permit privilege escalation in certain configurations. The
    documentation does not advise against the use of passdb definitions that have the same driver and args
    settings. One such configuration would be where an administrator wishes to use the same PAM configuration
    or passwd file for both normal and master users but use the username_filter setting to restrict which of
    the users is able to be a master user. (CVE-2022-30550)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5509-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30550");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-auth-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-imapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-lmtpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-lucene");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-managesieved");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-pop3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-sieve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-solr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-submissiond");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mail-stack-delivery");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release || '20.04' >< os_release || '21.10' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.10 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'dovecot-core', 'pkgver': '1:2.2.33.2-1ubuntu4.8'},
    {'osver': '18.04', 'pkgname': 'dovecot-dev', 'pkgver': '1:2.2.33.2-1ubuntu4.8'},
    {'osver': '18.04', 'pkgname': 'dovecot-gssapi', 'pkgver': '1:2.2.33.2-1ubuntu4.8'},
    {'osver': '18.04', 'pkgname': 'dovecot-imapd', 'pkgver': '1:2.2.33.2-1ubuntu4.8'},
    {'osver': '18.04', 'pkgname': 'dovecot-ldap', 'pkgver': '1:2.2.33.2-1ubuntu4.8'},
    {'osver': '18.04', 'pkgname': 'dovecot-lmtpd', 'pkgver': '1:2.2.33.2-1ubuntu4.8'},
    {'osver': '18.04', 'pkgname': 'dovecot-managesieved', 'pkgver': '1:2.2.33.2-1ubuntu4.8'},
    {'osver': '18.04', 'pkgname': 'dovecot-mysql', 'pkgver': '1:2.2.33.2-1ubuntu4.8'},
    {'osver': '18.04', 'pkgname': 'dovecot-pgsql', 'pkgver': '1:2.2.33.2-1ubuntu4.8'},
    {'osver': '18.04', 'pkgname': 'dovecot-pop3d', 'pkgver': '1:2.2.33.2-1ubuntu4.8'},
    {'osver': '18.04', 'pkgname': 'dovecot-sieve', 'pkgver': '1:2.2.33.2-1ubuntu4.8'},
    {'osver': '18.04', 'pkgname': 'dovecot-solr', 'pkgver': '1:2.2.33.2-1ubuntu4.8'},
    {'osver': '18.04', 'pkgname': 'dovecot-sqlite', 'pkgver': '1:2.2.33.2-1ubuntu4.8'},
    {'osver': '18.04', 'pkgname': 'mail-stack-delivery', 'pkgver': '1:2.2.33.2-1ubuntu4.8'},
    {'osver': '20.04', 'pkgname': 'dovecot-auth-lua', 'pkgver': '1:2.3.7.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'dovecot-core', 'pkgver': '1:2.3.7.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'dovecot-dev', 'pkgver': '1:2.3.7.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'dovecot-gssapi', 'pkgver': '1:2.3.7.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'dovecot-imapd', 'pkgver': '1:2.3.7.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'dovecot-ldap', 'pkgver': '1:2.3.7.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'dovecot-lmtpd', 'pkgver': '1:2.3.7.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'dovecot-lucene', 'pkgver': '1:2.3.7.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'dovecot-managesieved', 'pkgver': '1:2.3.7.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'dovecot-mysql', 'pkgver': '1:2.3.7.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'dovecot-pgsql', 'pkgver': '1:2.3.7.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'dovecot-pop3d', 'pkgver': '1:2.3.7.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'dovecot-sieve', 'pkgver': '1:2.3.7.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'dovecot-solr', 'pkgver': '1:2.3.7.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'dovecot-sqlite', 'pkgver': '1:2.3.7.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'dovecot-submissiond', 'pkgver': '1:2.3.7.2-1ubuntu3.6'},
    {'osver': '20.04', 'pkgname': 'mail-stack-delivery', 'pkgver': '1:2.3.7.2-1ubuntu3.6'},
    {'osver': '21.10', 'pkgname': 'dovecot-auth-lua', 'pkgver': '1:2.3.13+dfsg1-1ubuntu3.1'},
    {'osver': '21.10', 'pkgname': 'dovecot-core', 'pkgver': '1:2.3.13+dfsg1-1ubuntu3.1'},
    {'osver': '21.10', 'pkgname': 'dovecot-dev', 'pkgver': '1:2.3.13+dfsg1-1ubuntu3.1'},
    {'osver': '21.10', 'pkgname': 'dovecot-gssapi', 'pkgver': '1:2.3.13+dfsg1-1ubuntu3.1'},
    {'osver': '21.10', 'pkgname': 'dovecot-imapd', 'pkgver': '1:2.3.13+dfsg1-1ubuntu3.1'},
    {'osver': '21.10', 'pkgname': 'dovecot-ldap', 'pkgver': '1:2.3.13+dfsg1-1ubuntu3.1'},
    {'osver': '21.10', 'pkgname': 'dovecot-lmtpd', 'pkgver': '1:2.3.13+dfsg1-1ubuntu3.1'},
    {'osver': '21.10', 'pkgname': 'dovecot-lucene', 'pkgver': '1:2.3.13+dfsg1-1ubuntu3.1'},
    {'osver': '21.10', 'pkgname': 'dovecot-managesieved', 'pkgver': '1:2.3.13+dfsg1-1ubuntu3.1'},
    {'osver': '21.10', 'pkgname': 'dovecot-mysql', 'pkgver': '1:2.3.13+dfsg1-1ubuntu3.1'},
    {'osver': '21.10', 'pkgname': 'dovecot-pgsql', 'pkgver': '1:2.3.13+dfsg1-1ubuntu3.1'},
    {'osver': '21.10', 'pkgname': 'dovecot-pop3d', 'pkgver': '1:2.3.13+dfsg1-1ubuntu3.1'},
    {'osver': '21.10', 'pkgname': 'dovecot-sieve', 'pkgver': '1:2.3.13+dfsg1-1ubuntu3.1'},
    {'osver': '21.10', 'pkgname': 'dovecot-solr', 'pkgver': '1:2.3.13+dfsg1-1ubuntu3.1'},
    {'osver': '21.10', 'pkgname': 'dovecot-sqlite', 'pkgver': '1:2.3.13+dfsg1-1ubuntu3.1'},
    {'osver': '21.10', 'pkgname': 'dovecot-submissiond', 'pkgver': '1:2.3.13+dfsg1-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'dovecot-auth-lua', 'pkgver': '1:2.3.16+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'dovecot-core', 'pkgver': '1:2.3.16+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'dovecot-dev', 'pkgver': '1:2.3.16+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'dovecot-gssapi', 'pkgver': '1:2.3.16+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'dovecot-imapd', 'pkgver': '1:2.3.16+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'dovecot-ldap', 'pkgver': '1:2.3.16+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'dovecot-lmtpd', 'pkgver': '1:2.3.16+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'dovecot-lucene', 'pkgver': '1:2.3.16+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'dovecot-managesieved', 'pkgver': '1:2.3.16+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'dovecot-mysql', 'pkgver': '1:2.3.16+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'dovecot-pgsql', 'pkgver': '1:2.3.16+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'dovecot-pop3d', 'pkgver': '1:2.3.16+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'dovecot-sieve', 'pkgver': '1:2.3.16+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'dovecot-solr', 'pkgver': '1:2.3.16+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'dovecot-sqlite', 'pkgver': '1:2.3.16+dfsg1-3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'dovecot-submissiond', 'pkgver': '1:2.3.16+dfsg1-3ubuntu2.1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dovecot-auth-lua / dovecot-core / dovecot-dev / dovecot-gssapi / etc');
}
