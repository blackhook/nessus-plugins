#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-31.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(132911);
  script_version("1.2");
  script_cvs_date("Date: 2020/01/17");

  script_cve_id("CVE-2017-7418", "CVE-2019-12815", "CVE-2019-18217", "CVE-2019-19269", "CVE-2019-19270");

  script_name(english:"openSUSE Security Update : proftpd (openSUSE-2020-31)");
  script_summary(english:"Check for the openSUSE-2020-31 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for proftpd fixes the following issues :

  - GeoIP has been discontinued by Maxmind (boo#1156210)
    This update removes module build for geoip see
    https://support.maxmind.com/geolite-legacy-discontinuati
    on-notice/

  - CVE-2019-19269: Fixed a NULL pointer dereference may
    occur when validating the certificate of a client
    connecting to the server (boo#1157803)

  - CVE-2019-19270: Fixed a Failure to check for the
    appropriate field of a CRL entry prevents some valid
    CRLs from being taken into account (boo#1157798)

  - CVE-2019-18217: Fixed remote unauthenticated
    denial-of-service due to incorrect handling of overly
    long commands (boo#1154600 gh#846)

Update to 1.3.6b

  - Fixed pre-authentication remote denial-of-service issue
    (Issue #846).

  - Backported fix for building mod_sql_mysql using MySQL 8
    (Issue #824).

Update to 1.3.6a :

  - Fixed symlink navigation (Bug#4332).

  - Fixed building of mod_sftp using OpenSSL 1.1.x releases
    (Issue#674).

  - Fixed SITE COPY honoring of <Limit> restrictions
    (Bug#4372).

  - Fixed segfault on login when using mod_sftp +
    mod_sftp_pam (Issue#656).

  - Fixed restarts when using mod_facl as a static module

  - Add missing Requires(pre): group(ftp) for Leap 15 and
    Tumbleweed (boo#1155834)

  - Add missing Requires(pre): user(ftp) for Leap 15 and
    Tumbleweed (boo#1155834)

  - Use pam_keyinit.so (boo#1144056)

  - Reduce hard dependency on systemd to only that which is
    necessary for building and installation.

update to 1.3.6 :

  - Support for using Redis for caching, logging; see the
    doc/howto/Redis.html documentation.

  - Fixed mod_sql_postgres SSL support (Issue #415).

  - Support building against LibreSSL instead of OpenSSL
    (Issue #361).

  - Better support on AIX for login restraictions (Bug
    #4285).

  - TimeoutLogin (and other timeouts) were not working
    properly for SFTP connections (Bug#4299).

  - Handling of the SIGILL and SIGINT signals, by the daemon
    process, now causes the child processes to be terminated
    as well (Issue #461).

  - RPM .spec file naming changed to conform to Fedora
    guidelines.

  - Fix for 'AllowChrootSymlinks off' checking each
    component for symlinks (CVE-2017-7418).

New Modules :

  - mod_redis, mod_tls_redis, mod_wrap2_redis With Redis now
    supported as a caching mechanism, similar to Memcache,
    there are now Redis-using modules: mod_redis (for
    configuring the Redis connection information),
    mod_tls_redis (for caching SSL sessions and OCSP
    information using Redis), and mod_wrap2_redis (for using
    ACLs stored in Redis).

Changed Modules :

  - mod_ban: The mod_ban module's BanCache directive can now
    use Redis-based caching; see
    doc/contrib/mod_ban.html#BanCache.

-New Configuration Directives

  - SQLPasswordArgon2, SQLPasswordScrypt

    The key lengths for Argon2 and Scrypt-based passwords
    are now configurable via these new directives;
    previously, the key length had been hardcoded to be 32
    bytes, which is not interoperable with all other
    implementations (Issue #454).

Changed Configuration Directives

  - AllowChrootSymlinks When 'AllowChrootSymlinks off' was
    used, only the last portion of the DefaultRoot path
    would be checked to see if it was a symlink. Now, each
    component of the DefaultRoot path will be checked to see
    if it is a symlink when 'AllowChrootSymlinks off' is
    used.

  - Include The Include directive can now be used within a
    <Limit> section, e.g.: <Limit LOGIN> Include
    /path/to/allowed.txt DenyAll </Limit> API Changes

  - A new JSON API has been added, for use by third-party
    modules."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155834"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156210"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.maxmind.com/geolite-legacy-discontinuation-notice/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected proftpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-radius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-radius-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"proftpd-1.3.6b-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-debuginfo-1.3.6b-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-debugsource-1.3.6b-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-devel-1.3.6b-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-lang-1.3.6b-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-ldap-1.3.6b-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-ldap-debuginfo-1.3.6b-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-mysql-1.3.6b-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-mysql-debuginfo-1.3.6b-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-pgsql-1.3.6b-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-pgsql-debuginfo-1.3.6b-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-radius-1.3.6b-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-radius-debuginfo-1.3.6b-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-sqlite-1.3.6b-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-sqlite-debuginfo-1.3.6b-lp151.3.6.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "proftpd / proftpd-debuginfo / proftpd-debugsource / proftpd-devel / etc");
}
