#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2347.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(130085);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/23");

  script_cve_id("CVE-2018-19052");

  script_name(english:"openSUSE Security Update : lighttpd (openSUSE-2019-2347)");
  script_summary(english:"Check for the openSUSE-2019-2347 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for lighttpd to version 1.4.54 fixes the following 
issues :

Security issues fixed :

  - CVE-2018-19052: Fixed a path traversal in mod_alias
    (boo#1115016).

  - Changed the default TLS configuration of lighttpd for
    better security out-of-the-box (boo#1087369)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153722"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected lighttpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_authn_gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_authn_gssapi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_authn_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_authn_ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_authn_mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_authn_mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_authn_pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_authn_pam-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_authn_sasl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_authn_sasl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_cml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_cml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_geoip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_magnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_magnet-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_maxminddb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_maxminddb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_mysql_vhost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_mysql_vhost-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_rrdtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_rrdtool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_trigger_b4_dl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_trigger_b4_dl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_vhostdb_dbi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_vhostdb_dbi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_vhostdb_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_vhostdb_ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_vhostdb_mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_vhostdb_mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_vhostdb_pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_vhostdb_pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_webdav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_webdav-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-debuginfo-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-debugsource-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_authn_gssapi-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_authn_gssapi-debuginfo-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_authn_ldap-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_authn_ldap-debuginfo-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_authn_mysql-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_authn_mysql-debuginfo-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_authn_pam-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_authn_pam-debuginfo-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_authn_sasl-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_authn_sasl-debuginfo-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_cml-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_cml-debuginfo-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_geoip-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_geoip-debuginfo-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_magnet-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_magnet-debuginfo-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_maxminddb-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_maxminddb-debuginfo-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_mysql_vhost-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_mysql_vhost-debuginfo-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_rrdtool-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_rrdtool-debuginfo-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_trigger_b4_dl-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_trigger_b4_dl-debuginfo-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_vhostdb_dbi-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_vhostdb_dbi-debuginfo-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_vhostdb_ldap-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_vhostdb_ldap-debuginfo-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_vhostdb_mysql-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_vhostdb_mysql-debuginfo-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_vhostdb_pgsql-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_vhostdb_pgsql-debuginfo-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_webdav-1.4.54-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lighttpd-mod_webdav-debuginfo-1.4.54-lp151.3.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lighttpd / lighttpd-debuginfo / lighttpd-debugsource / etc");
}
