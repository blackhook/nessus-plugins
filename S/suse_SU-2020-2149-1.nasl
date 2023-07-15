#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:2149-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(139407);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2020-1720");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : postgresql10 / postgresql12 (SUSE-SU-2020:2149-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for postgresql10 and postgresql12 fixes the following
issues :

postgresql10 was updated to 10.13 (bsc#1171924).

https://www.postgresql.org/about/news/2038/
https://www.postgresql.org/docs/10/release-10-13.html

postgresql10 was updated to 10.12 (CVE-2020-1720, bsc#1163985)

https://www.postgresql.org/about/news/2011/

https://www.postgresql.org/docs/10/release-10-12.html

postgresql10 was updated to 10.11 :

https://www.postgresql.org/about/news/1994/

https://www.postgresql.org/docs/10/release-10-11.html

postgresql12 was updated to 12.3 (bsc#1171924).

Bug Fixes and Improvements :

Several fixes for GENERATED columns, including an issue where it was
possible to crash or corrupt data in a table when the output of the
generated column was the exact copy of a physical column on the table,
e.g. if the expression called a function which could return its own
input.

Several fixes for ALTER TABLE, including ensuring the SET STORAGE
directive is propagated to a table's indexes.

Fix a potential race condition when using DROP OWNED BY while another
session is deleting the same objects.

Allow for a partition to be detached when it has inherited ROW
triggers.

Several fixes for REINDEX CONCURRENTLY, particularly with issues when
a REINDEX CONCURRENTLY operation fails.

Fix crash when COLLATE is applied to an uncollatable type in a
partition bound expression.

Fix performance regression in floating point overflow/underflow
detection.

Several fixes for full text search, particularly with phrase
searching.

Fix query-lifespan memory leak for a set-returning function used in a
query's FROM clause.

Several reporting fixes for the output of VACUUM VERBOSE.

Allow input of type circle to accept the format (x,y),r, which is
specified in the documentation.

Allow for the get_bit() and set_bit() functions to not fail on bytea
strings longer than 256MB.

Avoid premature recycling of WAL segments during crash recovery, which
could lead to WAL segments being recycled before being archived.

Avoid attempting to fetch nonexistent WAL files from archive storage
during recovery by skipping irrelevant timelines.

Several fixes for logical replication and replication slots.

Fix several race conditions in synchronous standby management,
including one that occurred when changing the
synchronous_standby_names setting.

Several fixes for GSSAPI support, include a fix for a memory leak that
occurred when using GSSAPI encryption.

Ensure that members of the pg_read_all_stats role can read all
statistics views.

Fix performance regression in information_schema.triggers view.

Fix memory leak in libpq when using sslmode=verify-full.

Fix crash in psql when attempting to re-establish a failed connection.

Allow tab-completion of the filename argument to \gx command in psql.

Add pg_dump support for ALTER ... DEPENDS ON EXTENSION.

Several other fixes for pg_dump, which include dumping comments on RLS
policies and postponing restore of event triggers until the end.

Ensure pg_basebackup generates valid tar files.

pg_checksums skips tablespace subdirectories that belong to a
different PostgreSQL major version

Several Windows compatibility fixes

This update also contains timezone tzdata release 2020a for DST law
changes in Morocco and the Canadian Yukon, plus historical corrections
for Shanghai. The America/Godthab zone has been renamed to
America/Nuuk to reflect current English usage ; however, the old name
remains available as a compatibility link. This also updates initdb's
list of known Windows time zone names to include recent additions.

For more details, check out :

https://www.postgresql.org/docs/12/release-12-3.html

Other fixes :

Let postgresqlXX conflict with postgresql-noarch < 12.0.1 to get a
clean and complete cutover to the new packaging schema.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1148643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1163985"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1171924"
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
    value:"https://www.suse.com/security/cve/CVE-2020-1720/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20202149-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?60847825"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2020-2149=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2020-2149=1

SUSE Linux Enterprise Module for Server Applications 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Server-Applications-15-SP1-2020-2149=1

SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Packagehub-Subpackages-15-SP1-2020-2149=1

SUSE Linux Enterprise Module for Basesystem 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP1-2020-2149=1

SUSE Linux Enterprise High Performance Computing 15-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-2149=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-2149=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1720");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libecpg6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpq5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpq5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-server-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libpq5-32bit-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libpq5-32bit-debuginfo-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libecpg6-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libecpg6-debuginfo-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libpq5-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libpq5-debuginfo-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"postgresql12-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"postgresql12-contrib-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"postgresql12-contrib-debuginfo-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"postgresql12-debuginfo-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"postgresql12-debugsource-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"postgresql12-devel-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"postgresql12-devel-debuginfo-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"postgresql12-plperl-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"postgresql12-plperl-debuginfo-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"postgresql12-plpython-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"postgresql12-plpython-debuginfo-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"postgresql12-pltcl-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"postgresql12-pltcl-debuginfo-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"postgresql12-server-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"postgresql12-server-debuginfo-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"postgresql12-server-devel-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"postgresql12-server-devel-debuginfo-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libecpg6-10.13-4.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libecpg6-debuginfo-10.13-4.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libpq5-10.13-4.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libpq5-debuginfo-10.13-4.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"postgresql10-10.13-4.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"postgresql10-contrib-10.13-4.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"postgresql10-contrib-debuginfo-10.13-4.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"postgresql10-debuginfo-10.13-4.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"postgresql10-debugsource-10.13-4.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"postgresql10-devel-10.13-4.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"postgresql10-devel-debuginfo-10.13-4.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"postgresql10-plperl-10.13-4.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"postgresql10-plperl-debuginfo-10.13-4.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"postgresql10-plpython-10.13-4.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"postgresql10-plpython-debuginfo-10.13-4.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"postgresql10-pltcl-10.13-4.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"postgresql10-pltcl-debuginfo-10.13-4.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"postgresql10-server-10.13-4.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"postgresql10-server-debuginfo-10.13-4.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libpq5-32bit-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libpq5-32bit-debuginfo-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libpq5-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libpq5-debuginfo-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"postgresql12-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"postgresql12-debuginfo-12.3-3.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"postgresql12-debugsource-12.3-3.8.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql10 / postgresql12");
}
