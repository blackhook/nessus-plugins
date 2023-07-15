#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1148.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118114);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"openSUSE Security Update : postgresql10 (openSUSE-2018-1148)");
  script_summary(english:"Check for the openSUSE-2018-1148 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for brings postgresql10 version 10.5 to openSUSE Leap
42.3. (FATE#325659 bnc#1108308)

This release marks the change of the versioning scheme for PostgreSQL
to a 'x.y' format. This means the next minor releases of PostgreSQL
will be 10.1, 10.2, ... and the next major release will be 11.

  - Logical Replication

Logical replication extends the current replication features of
PostgreSQL with the ability to send modifications on a per-database
and per-table level to different PostgreSQL databases. Users can now
fine-tune the data replicated to various database clusters and will
have the ability to perform zero-downtime upgrades to future major
PostgreSQL versions.

  - Declarative Table Partitioning

Table partitioning has existed for years in PostgreSQL but required a
user to maintain a nontrivial set of rules and triggers for the
partitioning to work. PostgreSQL 10 introduces a table partitioning
syntax that lets users easily create and maintain range and list
partitioned tables.

  - Improved Query Parallelism

PostgreSQL 10 provides better support for parallelized queries by
allowing more parts of the query execution process to be parallelized.
Improvements include additional types of data scans that are
parallelized as well as optimizations when the data is recombined,
such as pre-sorting. These enhancements allow results to be returned
more quickly.

  - Quorum Commit for Synchronous Replication

PostgreSQL 10 introduces quorum commit for synchronous replication,
which allows for flexibility in how a primary database receives
acknowledgement that changes were successfully written to remote
replicas.

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108308"
  );
  # https://features.opensuse.org/325659
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql10 packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-init");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-libs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"libecpg6-10.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libecpg6-debuginfo-10.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpq5-10.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpq5-debuginfo-10.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql-init-10-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql10-10.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql10-contrib-10.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql10-contrib-debuginfo-10.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql10-debuginfo-10.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql10-debugsource-10.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql10-devel-10.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql10-devel-debuginfo-10.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql10-libs-debugsource-10.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql10-plperl-10.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql10-plperl-debuginfo-10.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql10-plpython-10.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql10-plpython-debuginfo-10.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql10-pltcl-10.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql10-pltcl-debuginfo-10.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql10-server-10.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql10-server-debuginfo-10.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql10-test-10.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libecpg6-32bit-10.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libecpg6-debuginfo-32bit-10.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpq5-32bit-10.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpq5-debuginfo-32bit-10.5-2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql-init / libecpg6 / libecpg6-32bit / libecpg6-debuginfo / etc");
}
