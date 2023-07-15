#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1227.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(139655);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2018-10915", "CVE-2018-10925", "CVE-2018-1115", "CVE-2019-10130", "CVE-2019-10208", "CVE-2020-14350", "CVE-2020-1720");
  script_xref(name:"IAVB", value:"2020-B-0047-S");

  script_name(english:"openSUSE Security Update : postgresql96 / postgresql10 and postgresql12  (openSUSE-2020-1227)");
  script_summary(english:"Check for the openSUSE-2020-1227 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for postgresql96, postgresql10 and postgresql12 fixes the
following issues :

postgresql10 was updated to 10.13 (bsc#1171924).

https://www.postgresql.org/about/news/2038/
https://www.postgresql.org/docs/10/release-10-13.html

postgresql10 was updated to 10.12 (CVE-2020-1720, bsc#1163985)

- https://www.postgresql.org/about/news/2011/

- https://www.postgresql.org/docs/10/release-10-12.html

postgresql10 was updated to 10.11 :

- https://www.postgresql.org/about/news/1994/

- https://www.postgresql.org/docs/10/release-10-11.html

postgresql12 was updated to 12.3 (bsc#1171924).

Bug Fixes and Improvements :

  - Several fixes for GENERATED columns, including an issue
    where it was possible to crash or corrupt data in a
    table when the output of the generated column was the
    exact copy of a physical column on the table, e.g. if
    the expression called a function which could return its
    own input.

  - Several fixes for ALTER TABLE, including ensuring the
    SET STORAGE directive is propagated to a table's
    indexes.

  - Fix a potential race condition when using DROP OWNED BY
    while another session is deleting the same objects.

  - Allow for a partition to be detached when it has
    inherited ROW triggers.

  - Several fixes for REINDEX CONCURRENTLY, particularly
    with issues when a REINDEX CONCURRENTLY operation fails.

  - Fix crash when COLLATE is applied to an uncollatable
    type in a partition bound expression.

  - Fix performance regression in floating point
    overflow/underflow detection.

  - Several fixes for full text search, particularly with
    phrase searching.

  - Fix query-lifespan memory leak for a set-returning
    function used in a query's FROM clause.

  - Several reporting fixes for the output of VACUUM
    VERBOSE.

  - Allow input of type circle to accept the format (x,y),r,
    which is specified in the documentation.

  - Allow for the get_bit() and set_bit() functions to not
    fail on bytea strings longer than 256MB.

  - Avoid premature recycling of WAL segments during crash
    recovery, which could lead to WAL segments being
    recycled before being archived.

  - Avoid attempting to fetch nonexistent WAL files from
    archive storage during recovery by skipping irrelevant
    timelines.

  - Several fixes for logical replication and replication
    slots.

  - Fix several race conditions in synchronous standby
    management, including one that occurred when changing
    the synchronous_standby_names setting.

  - Several fixes for GSSAPI support, include a fix for a
    memory leak that occurred when using GSSAPI encryption.

  - Ensure that members of the pg_read_all_stats role can
    read all statistics views.

  - Fix performance regression in
    information_schema.triggers view.

  - Fix memory leak in libpq when using sslmode=verify-full.

  - Fix crash in psql when attempting to re-establish a
    failed connection.

  - Allow tab-completion of the filename argument to \gx
    command in psql.

  - Add pg_dump support for ALTER ... DEPENDS ON EXTENSION.

  - Several other fixes for pg_dump, which include dumping
    comments on RLS policies and postponing restore of event
    triggers until the end.

  - Ensure pg_basebackup generates valid tar files.

  - pg_checksums skips tablespace subdirectories that belong
    to a different PostgreSQL major version

  - Several Windows compatibility fixes

This update also contains timezone tzdata release 2020a for DST law
changes in Morocco and the Canadian Yukon, plus historical corrections
for Shanghai. The America/Godthab zone has been renamed to
America/Nuuk to reflect current English usage ; however, the old name
remains available as a compatibility link. This also updates initdb's
list of known Windows time zone names to include recent additions.

For more details, check out :

  - https://www.postgresql.org/docs/12/release-12-3.html

Other fixes :

  - Let postgresqlXX conflict with postgresql-noarch <
    12.0.1 to get a clean and complete cutover to the new
    packaging schema.

postgresql96 was updated to 9.6.19 :

  - CVE-2020-14350, boo#1175194: Make contrib modules'
    installation scripts more secure.

  - https://www.postgresql.org/docs/9.6/release-9-6-19.html

  - Pack the /usr/lib/postgresql symlink only into the main
    package.

  - Let postgresqlXX conflict with postgresql-noarch <
    12.0.1 to get a clean and complete cutover to the new
    packaging schema.

  - update to 9.6.18 (boo#1171924).
    https://www.postgresql.org/about/news/2038/
    https://www.postgresql.org/docs/9.6/release-9-6-18.html

  - Unify the spec file to work across all current
    PostgreSQL versions to simplify future maintenance.

  - Move from the 'libs' build flavour to a 'mini' package
    that will only be used inside the build service and not
    get shipped, to avoid confusion with the debuginfo
    packages (boo#1148643).

  - update to 9.6.17 (CVE-2020-1720, boo#1163985)
    https://www.postgresql.org/about/news/2011/
    https://www.postgresql.org/docs/9.6/release-9-6-17.html

  - use and package the sha256 checksum for for source

  - update to 9.6.16:
    https://www.postgresql.org/about/news/1994/
    https://www.postgresql.org/docs/9.6/release-9-6-16.html

  - add requires to the devel package for the libs that are
    returned by pg_config --libs

  - Update to 9.6.15 :

  - https://www.postgresql.org/about/news/1960/

  - https://www.postgresql.org/docs/9.6/release-9-6-15.html

  - CVE-2019-10208, boo#1145092: TYPE in pg_temp executes
    arbitrary SQL during SECURITY DEFINER execution.

  - Use FAT LTO objects in order to provide proper static
    library.

  - Update to 9.6.14:
    https://www.postgresql.org/docs/9.6/release-9-6-14.html

  - Update to 9.6.13 :

  - https://www.postgresql.org/docs/9.6/release-9-6-13.html

  - https://www.postgresql.org/about/news/1939/

  - CVE-2019-10130, boo#1134689: Prevent row-level security
    policies from being bypassed via selectivity estimators.

  - Make the server-devel package exclusive across versions.

  - Update to 9.6.12 :

  - https://www.postgresql.org/docs/9.6/release-9-6-12.html

  - https://www.postgresql.org/about/news/1920/

  - By default, panic instead of retrying after fsync()
    failure, to avoid possible data corruption.

  - Numerous other bug fixes.

  - Overhaul README.SUSE

  - Update to 9.6.11 :

  - Numerous bug fixes, see the release notes:
    https://www.postgresql.org/docs/9.6/release-9-6-11.html

  - Remove unneeded library dependencies from PGXS.

  - add provides for the new server-devel package that will
    be introduced in postgresql 11

  - Update to 9.6.10:
    https://www.postgresql.org/docs/current/static/release-9
    -6-10.html

  - CVE-2018-10915, boo#1104199: Fix failure to reset
    libpq's state fully between connection attempts.

  - CVE-2018-10925, boo#1104202: Fix INSERT ... ON CONFLICT
    UPDATE through a view that isn't just SELECT * FROM ...

  - Update to 9.6.9:
    https://www.postgresql.org/about/news/1851/
    https://www.postgresql.org/docs/current/static/release-9
    -6-9.html A dump/restore is not required for those
    running 9.6.X. However, if you use the adminpack
    extension, you should update it as per the first
    changelog entry below. Also, if the function marking
    mistakes mentioned in the second and third changelog
    entries below affect you, you will want to take steps to
    correct your database catalogs.

  - CVE-2018-1115, boo#1091610: Remove public execute
    privilege from contrib/adminpack's pg_logfile_rotate()
    function pg_logfile_rotate() is a deprecated wrapper for
    the core function pg_rotate_logfile(). When that
    function was changed to rely on SQL privileges for
    access control rather than a hard-coded superuser check,
    pg_logfile_rotate() should have been updated as well,
    but the need for this was missed. Hence, if adminpack is
    installed, any user could request a logfile rotation,
    creating a minor security issue. After installing this
    update, administrators should update adminpack by
    performing ALTER EXTENSION adminpack UPDATE in each
    database in which adminpack is installed.

  - Fix incorrect volatility markings on a few built-in
    functions

  - Fix incorrect parallel-safety markings on a few built-in
    functions.

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163985"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/about/news/1851/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/about/news/1920/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/about/news/1939/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/about/news/1960/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/about/news/1994/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/about/news/2011/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/about/news/2038/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/10/release-10-11.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/10/release-10-12.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/10/release-10-13.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/12/release-12-3.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/9.6/release-9-6-11.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/9.6/release-9-6-12.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/9.6/release-9-6-13.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/9.6/release-9-6-14.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/9.6/release-9-6-15.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/9.6/release-9-6-16.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/9.6/release-9-6-17.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/9.6/release-9-6-18.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/9.6/release-9-6-19.html"
  );
  # https://www.postgresql.org/docs/current/static/release-9-6-10.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/current/release-9-6-10.html"
  );
  # https://www.postgresql.org/docs/current/static/release-9-6-9.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/current/release-9-6-9.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected postgresql96 / postgresql10 and postgresql12  packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10208");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-llvmjit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-llvmjit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-llvmjit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-server-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"postgresql-12.0.1-lp151.6.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql-contrib-12.0.1-lp151.6.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql-devel-12.0.1-lp151.6.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql-llvmjit-12.0.1-lp151.6.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql-plperl-12.0.1-lp151.6.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql-plpython-12.0.1-lp151.6.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql-pltcl-12.0.1-lp151.6.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql-server-12.0.1-lp151.6.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql-server-devel-12.0.1-lp151.6.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql-test-12.0.1-lp151.6.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-10.13-lp151.2.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-contrib-10.13-lp151.2.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-contrib-debuginfo-10.13-lp151.2.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-debuginfo-10.13-lp151.2.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-debugsource-10.13-lp151.2.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-devel-10.13-lp151.2.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-devel-debuginfo-10.13-lp151.2.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-plperl-10.13-lp151.2.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-plperl-debuginfo-10.13-lp151.2.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-plpython-10.13-lp151.2.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-plpython-debuginfo-10.13-lp151.2.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-pltcl-10.13-lp151.2.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-pltcl-debuginfo-10.13-lp151.2.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-server-10.13-lp151.2.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-server-debuginfo-10.13-lp151.2.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-test-10.13-lp151.2.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql96-9.6.19-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql96-contrib-9.6.19-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql96-contrib-debuginfo-9.6.19-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql96-debuginfo-9.6.19-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql96-debugsource-9.6.19-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql96-devel-9.6.19-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql96-devel-debuginfo-9.6.19-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql96-plperl-9.6.19-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql96-plperl-debuginfo-9.6.19-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql96-plpython-9.6.19-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql96-plpython-debuginfo-9.6.19-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql96-pltcl-9.6.19-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql96-pltcl-debuginfo-9.6.19-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql96-server-9.6.19-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql96-server-debuginfo-9.6.19-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql96-test-9.6.19-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libecpg6-12.3-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libecpg6-debuginfo-12.3-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libpq5-12.3-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libpq5-debuginfo-12.3-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"postgresql12-12.3-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"postgresql12-contrib-12.3-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"postgresql12-contrib-debuginfo-12.3-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"postgresql12-debuginfo-12.3-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"postgresql12-debugsource-12.3-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"postgresql12-devel-12.3-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"postgresql12-devel-debuginfo-12.3-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"postgresql12-llvmjit-12.3-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"postgresql12-llvmjit-debuginfo-12.3-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"postgresql12-plperl-12.3-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"postgresql12-plperl-debuginfo-12.3-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"postgresql12-plpython-12.3-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"postgresql12-plpython-debuginfo-12.3-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"postgresql12-pltcl-12.3-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"postgresql12-pltcl-debuginfo-12.3-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"postgresql12-server-12.3-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"postgresql12-server-debuginfo-12.3-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"postgresql12-server-devel-12.3-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"postgresql12-server-devel-debuginfo-12.3-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"postgresql12-test-12.3-lp151.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-devel / etc");
}
