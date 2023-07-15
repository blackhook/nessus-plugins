#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:1652-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149804);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/24");

  script_cve_id("CVE-2021-21309", "CVE-2021-29477", "CVE-2021-29478");

  script_name(english:"SUSE SLES15 Security Update : redis (SUSE-SU-2021:1652-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for redis fixes the following issues :

redis was updated to 6.0.13 :

CVE-2021-29477: Integer overflow in STRALGO LCS command (bsc#1185729)

CVE-2021-29478: Integer overflow in COPY command for large intsets
(bsc#1185730)

Cluster: Skip unnecessary check which may prevent failure detection

Fix performance regression in BRPOP on Redis 6.0

Fix edge-case when a module client is unblocked

redis 6.0.12 :

Fix compilation error on non-glibc systems if jemalloc is not used

redis 6.0.11 :

CVE-2021-21309: Avoid 32-bit overflows when proto-max-bulk-len is set
high (bsc#1182657)

Fix handling of threaded IO and CLIENT PAUSE (failover), could lead to
data loss or a crash

Fix the selection of a random element from large hash tables

Fix broken protocol in client tracking tracking-redir-broken message

XINFO able to access expired keys on a replica

Fix broken protocol in redis-benchmark when used with -a or

--dbnum

Avoid assertions (on older kernels) when testing arm64 CoW bug

CONFIG REWRITE should honor umask settings

Fix firstkey,lastkey,step in COMMAND command for some commands

RM_ZsetRem: Delete key if empty, the bug could leave empty zset keys

Switch systemd type of the sentinel service from notify to simple.
This can be reverted when updating to 6.2 which fixes
https://github.com/redis/redis/issues/7284 .

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1182657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1185729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1185730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/redis/redis/issues/7284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-21309/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-29477/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-29478/"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20211652-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8ec6152"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Server Applications 15-SP3 :

zypper in -t patch
SUSE-SLE-Module-Server-Applications-15-SP3-2021-1652=1

SUSE Linux Enterprise Module for Server Applications 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Server-Applications-15-SP2-2021-1652=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:redis-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:redis-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"3", reference:"redis-6.0.13-1.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"redis-debuginfo-6.0.13-1.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"redis-debugsource-6.0.13-1.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"redis-6.0.13-1.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"redis-debuginfo-6.0.13-1.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"redis-debugsource-6.0.13-1.10.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "redis");
}
