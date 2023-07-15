##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4674-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144710);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2020-24386", "CVE-2020-25275");
  script_xref(name:"USN", value:"4674-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 : Dovecot vulnerabilities (USN-4674-1)");
  script_summary(english:"Checks the dpkg output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4674-1 advisory.

  - An issue was discovered in Dovecot before 2.3.13. By using IMAP IDLE, an authenticated attacker can
    trigger unhibernation via attacker-controlled parameters, leading to access to other users' email messages
    (and path disclosure). (CVE-2020-24386)

  - Dovecot before 2.3.13 has Improper Input Validation in lda, lmtp, and imap, leading to an application
    crash via a crafted email message with certain choices for ten thousand MIME parts. (CVE-2020-25275)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4674-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24386");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
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

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(16\.04|18\.04|20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'dovecot-core', 'pkgver': '1:2.2.22-1ubuntu2.14'},
    {'osver': '16.04', 'pkgname': 'dovecot-dev', 'pkgver': '1:2.2.22-1ubuntu2.14'},
    {'osver': '16.04', 'pkgname': 'dovecot-gssapi', 'pkgver': '1:2.2.22-1ubuntu2.14'},
    {'osver': '16.04', 'pkgname': 'dovecot-imapd', 'pkgver': '1:2.2.22-1ubuntu2.14'},
    {'osver': '16.04', 'pkgname': 'dovecot-ldap', 'pkgver': '1:2.2.22-1ubuntu2.14'},
    {'osver': '16.04', 'pkgname': 'dovecot-lmtpd', 'pkgver': '1:2.2.22-1ubuntu2.14'},
    {'osver': '16.04', 'pkgname': 'dovecot-lucene', 'pkgver': '1:2.2.22-1ubuntu2.14'},
    {'osver': '16.04', 'pkgname': 'dovecot-managesieved', 'pkgver': '1:2.2.22-1ubuntu2.14'},
    {'osver': '16.04', 'pkgname': 'dovecot-mysql', 'pkgver': '1:2.2.22-1ubuntu2.14'},
    {'osver': '16.04', 'pkgname': 'dovecot-pgsql', 'pkgver': '1:2.2.22-1ubuntu2.14'},
    {'osver': '16.04', 'pkgname': 'dovecot-pop3d', 'pkgver': '1:2.2.22-1ubuntu2.14'},
    {'osver': '16.04', 'pkgname': 'dovecot-sieve', 'pkgver': '1:2.2.22-1ubuntu2.14'},
    {'osver': '16.04', 'pkgname': 'dovecot-solr', 'pkgver': '1:2.2.22-1ubuntu2.14'},
    {'osver': '16.04', 'pkgname': 'dovecot-sqlite', 'pkgver': '1:2.2.22-1ubuntu2.14'},
    {'osver': '16.04', 'pkgname': 'mail-stack-delivery', 'pkgver': '1:2.2.22-1ubuntu2.14'},
    {'osver': '18.04', 'pkgname': 'dovecot-core', 'pkgver': '1:2.2.33.2-1ubuntu4.7'},
    {'osver': '18.04', 'pkgname': 'dovecot-dev', 'pkgver': '1:2.2.33.2-1ubuntu4.7'},
    {'osver': '18.04', 'pkgname': 'dovecot-gssapi', 'pkgver': '1:2.2.33.2-1ubuntu4.7'},
    {'osver': '18.04', 'pkgname': 'dovecot-imapd', 'pkgver': '1:2.2.33.2-1ubuntu4.7'},
    {'osver': '18.04', 'pkgname': 'dovecot-ldap', 'pkgver': '1:2.2.33.2-1ubuntu4.7'},
    {'osver': '18.04', 'pkgname': 'dovecot-lmtpd', 'pkgver': '1:2.2.33.2-1ubuntu4.7'},
    {'osver': '18.04', 'pkgname': 'dovecot-managesieved', 'pkgver': '1:2.2.33.2-1ubuntu4.7'},
    {'osver': '18.04', 'pkgname': 'dovecot-mysql', 'pkgver': '1:2.2.33.2-1ubuntu4.7'},
    {'osver': '18.04', 'pkgname': 'dovecot-pgsql', 'pkgver': '1:2.2.33.2-1ubuntu4.7'},
    {'osver': '18.04', 'pkgname': 'dovecot-pop3d', 'pkgver': '1:2.2.33.2-1ubuntu4.7'},
    {'osver': '18.04', 'pkgname': 'dovecot-sieve', 'pkgver': '1:2.2.33.2-1ubuntu4.7'},
    {'osver': '18.04', 'pkgname': 'dovecot-solr', 'pkgver': '1:2.2.33.2-1ubuntu4.7'},
    {'osver': '18.04', 'pkgname': 'dovecot-sqlite', 'pkgver': '1:2.2.33.2-1ubuntu4.7'},
    {'osver': '18.04', 'pkgname': 'mail-stack-delivery', 'pkgver': '1:2.2.33.2-1ubuntu4.7'},
    {'osver': '20.04', 'pkgname': 'dovecot-auth-lua', 'pkgver': '1:2.3.7.2-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'dovecot-core', 'pkgver': '1:2.3.7.2-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'dovecot-dev', 'pkgver': '1:2.3.7.2-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'dovecot-gssapi', 'pkgver': '1:2.3.7.2-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'dovecot-imapd', 'pkgver': '1:2.3.7.2-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'dovecot-ldap', 'pkgver': '1:2.3.7.2-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'dovecot-lmtpd', 'pkgver': '1:2.3.7.2-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'dovecot-lucene', 'pkgver': '1:2.3.7.2-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'dovecot-managesieved', 'pkgver': '1:2.3.7.2-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'dovecot-mysql', 'pkgver': '1:2.3.7.2-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'dovecot-pgsql', 'pkgver': '1:2.3.7.2-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'dovecot-pop3d', 'pkgver': '1:2.3.7.2-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'dovecot-sieve', 'pkgver': '1:2.3.7.2-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'dovecot-solr', 'pkgver': '1:2.3.7.2-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'dovecot-sqlite', 'pkgver': '1:2.3.7.2-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'dovecot-submissiond', 'pkgver': '1:2.3.7.2-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'mail-stack-delivery', 'pkgver': '1:2.3.7.2-1ubuntu3.3'},
    {'osver': '20.10', 'pkgname': 'dovecot-auth-lua', 'pkgver': '1:2.3.11.3+dfsg1-2ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'dovecot-core', 'pkgver': '1:2.3.11.3+dfsg1-2ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'dovecot-dev', 'pkgver': '1:2.3.11.3+dfsg1-2ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'dovecot-gssapi', 'pkgver': '1:2.3.11.3+dfsg1-2ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'dovecot-imapd', 'pkgver': '1:2.3.11.3+dfsg1-2ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'dovecot-ldap', 'pkgver': '1:2.3.11.3+dfsg1-2ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'dovecot-lmtpd', 'pkgver': '1:2.3.11.3+dfsg1-2ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'dovecot-lucene', 'pkgver': '1:2.3.11.3+dfsg1-2ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'dovecot-managesieved', 'pkgver': '1:2.3.11.3+dfsg1-2ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'dovecot-mysql', 'pkgver': '1:2.3.11.3+dfsg1-2ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'dovecot-pgsql', 'pkgver': '1:2.3.11.3+dfsg1-2ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'dovecot-pop3d', 'pkgver': '1:2.3.11.3+dfsg1-2ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'dovecot-sieve', 'pkgver': '1:2.3.11.3+dfsg1-2ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'dovecot-solr', 'pkgver': '1:2.3.11.3+dfsg1-2ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'dovecot-sqlite', 'pkgver': '1:2.3.11.3+dfsg1-2ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'dovecot-submissiond', 'pkgver': '1:2.3.11.3+dfsg1-2ubuntu0.1'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
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
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dovecot-auth-lua / dovecot-core / dovecot-dev / dovecot-gssapi / etc');
}