#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3122. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(165510);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/27");

  script_cve_id("CVE-2021-33515", "CVE-2022-30550");

  script_name(english:"Debian DLA-3122-1 : dovecot - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3122 advisory.

  - The submission service in Dovecot before 2.3.15 allows STARTTLS command injection in lib-smtp. Sensitive
    information can be redirected to an attacker-controlled address. (CVE-2021-33515)

  - An issue was discovered in the auth component in Dovecot 2.2 and 2.3 before 2.3.20. When two passdb
    configuration entries exist with the same driver and args settings, incorrect username_filter and
    mechanism settings can be applied to passdb definitions. These incorrectly applied settings can lead to an
    unintended security configuration and can permit privilege escalation in certain configurations. The
    documentation does not advise against the use of passdb definitions that have the same driver and args
    settings. One such configuration would be where an administrator wishes to use the same PAM configuration
    or passwd file for both normal and master users but use the username_filter setting to restrict which of
    the users is able to be a master user. (CVE-2022-30550)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/dovecot");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3122");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33515");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-30550");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/dovecot");
  script_set_attribute(attribute:"solution", value:
"Upgrade the dovecot packages.

For Debian 10 buster, these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33515");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-30550");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-auth-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-imapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-lmtpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-lucene");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-managesieved");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-pop3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-sieve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-solr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-submissiond");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'dovecot-auth-lua', 'reference': '1:2.3.4.1-5+deb10u7'},
    {'release': '10.0', 'prefix': 'dovecot-core', 'reference': '1:2.3.4.1-5+deb10u7'},
    {'release': '10.0', 'prefix': 'dovecot-dev', 'reference': '1:2.3.4.1-5+deb10u7'},
    {'release': '10.0', 'prefix': 'dovecot-gssapi', 'reference': '1:2.3.4.1-5+deb10u7'},
    {'release': '10.0', 'prefix': 'dovecot-imapd', 'reference': '1:2.3.4.1-5+deb10u7'},
    {'release': '10.0', 'prefix': 'dovecot-ldap', 'reference': '1:2.3.4.1-5+deb10u7'},
    {'release': '10.0', 'prefix': 'dovecot-lmtpd', 'reference': '1:2.3.4.1-5+deb10u7'},
    {'release': '10.0', 'prefix': 'dovecot-lucene', 'reference': '1:2.3.4.1-5+deb10u7'},
    {'release': '10.0', 'prefix': 'dovecot-managesieved', 'reference': '1:2.3.4.1-5+deb10u7'},
    {'release': '10.0', 'prefix': 'dovecot-mysql', 'reference': '1:2.3.4.1-5+deb10u7'},
    {'release': '10.0', 'prefix': 'dovecot-pgsql', 'reference': '1:2.3.4.1-5+deb10u7'},
    {'release': '10.0', 'prefix': 'dovecot-pop3d', 'reference': '1:2.3.4.1-5+deb10u7'},
    {'release': '10.0', 'prefix': 'dovecot-sieve', 'reference': '1:2.3.4.1-5+deb10u7'},
    {'release': '10.0', 'prefix': 'dovecot-solr', 'reference': '1:2.3.4.1-5+deb10u7'},
    {'release': '10.0', 'prefix': 'dovecot-sqlite', 'reference': '1:2.3.4.1-5+deb10u7'},
    {'release': '10.0', 'prefix': 'dovecot-submissiond', 'reference': '1:2.3.4.1-5+deb10u7'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dovecot-auth-lua / dovecot-core / dovecot-dev / dovecot-gssapi / etc');
}
