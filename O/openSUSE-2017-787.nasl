#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-787.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101284);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-2669");

  script_name(english:"openSUSE Security Update : dovecot22 (openSUSE-2017-787)");
  script_summary(english:"Check for the openSUSE-2017-787 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for dovecot22 to version 2.2.30.2 fixes the following
issues :

This security issue was fixed :

  - CVE-2017-2669: Don't double-expand %variables in keys.
    If dict was used as the authentication passdb, using
    specially crafted %variables in the username could be
    used to cause DoS (bsc#1032248)

Additionally stronger SSL default ciphers are now used.

This non-security issue was fixed :

  - Remove all references /etc/ssl/certs/. It should not be
    used anymore (bsc#932386)

The version 2.2.30.2 also includes many fixes and enhancements :

  - Multiple failed authentications within short time caused
    crashes.

  - Use timing safe comparisons for everything related to
    passwords.

  - Master process now sends SIGQUIT to all running children
    at shutdown, which instructs them to close all the
    socket listeners immediately. Restarting Dovecot should
    no longer fail due to some processes keeping the
    listeners open for a long time.

  - Add passdb ( mechanisms=none ) to match separate passdb
    lookup.

  - Add passdb ( username_filter ) to use passdb only if
    user matches the filter.

  - Add dsync_commit_msgs_interval setting. It attempts to
    commit the transaction after saving this many new
    messages.

  - Support imapc_features=search without ESEARCH extension.

  - Add imapc_features=fetch-bodystructure to pass through
    remote server's FETCH BODY and BODYSTRUCTURE.

  - Add quota=imapc backend to use GETQUOTA/GETQUOTAROOT on
    the remote server.

  - Add allow_invalid_cert and ssl_ca_file parameters.

  - If dovecot.index.cache corruption is detected, reset
    only the one corrupted mail instead of the whole file.

  - Add 'firstsaved' field to doveadm mailbox status.

  - Add old host's up/down and vhost count as parameters to
    director_flush_socket.

  - More fixes to automatically fix corruption in
    dovecot.list.index.

  - Fix support for dsync_features=empty-header-workaround.

  - IMAP NOTIFY wasn't working for non-INBOX if IMAP client
    hadn't enabled modseq tracking via CONDSTORE/QRESYNC.

  - Fix fts-lucene it to work again with mbox format.

  - Some internal error messages may have contained garbage
    in v2.2.29.

  - Re-encrypt when copying/moving mails and per-mailbox
    keys are used, otherwise the copied mails can't be
    opened.

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=854512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=932386"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dovecot22 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-backend-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-backend-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-backend-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-backend-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-backend-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-backend-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-fts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-fts-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-fts-lucene");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-fts-lucene-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-fts-solr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-fts-solr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-fts-squat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-fts-squat-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"dovecot22-2.2.30.2-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"dovecot22-backend-mysql-2.2.30.2-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"dovecot22-backend-mysql-debuginfo-2.2.30.2-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"dovecot22-backend-pgsql-2.2.30.2-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"dovecot22-backend-pgsql-debuginfo-2.2.30.2-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"dovecot22-backend-sqlite-2.2.30.2-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"dovecot22-backend-sqlite-debuginfo-2.2.30.2-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"dovecot22-debuginfo-2.2.30.2-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"dovecot22-debugsource-2.2.30.2-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"dovecot22-devel-2.2.30.2-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"dovecot22-fts-2.2.30.2-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"dovecot22-fts-debuginfo-2.2.30.2-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"dovecot22-fts-lucene-2.2.30.2-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"dovecot22-fts-lucene-debuginfo-2.2.30.2-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"dovecot22-fts-solr-2.2.30.2-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"dovecot22-fts-solr-debuginfo-2.2.30.2-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"dovecot22-fts-squat-2.2.30.2-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"dovecot22-fts-squat-debuginfo-2.2.30.2-5.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dovecot22 / dovecot22-backend-mysql / etc");
}
