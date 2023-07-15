#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:3729-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(143705);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/11");

  script_cve_id("CVE-2019-12625", "CVE-2019-12900", "CVE-2019-15961", "CVE-2020-3123", "CVE-2020-3327", "CVE-2020-3341", "CVE-2020-3350", "CVE-2020-3481");

  script_name(english:"SUSE SLES12 Security Update : clamav (SUSE-SU-2020:3729-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for clamav fixes the following issues :

clamav was updated to 0.103.0 to implement jsc#ECO-3010 and
bsc#1118459.

clamd can now reload the signature database without blocking scanning.
This multi-threaded database reload improvement was made possible
thanks to a community effort.

  - Non-blocking database reloads are now the default
    behavior. Some systems that are more constrained on RAM
    may need to disable non-blocking reloads as it will
    temporarily consume two times as much memory. We added a
    new clamd config option ConcurrentDatabaseReload, which
    may be set to no.

Fix clamav-milter.service (requires clamd.service to run)

Fix freshclam crash in FIPS mode. (bsc#1119353)

Update to version 0.102.4 :

Accumulated security fixes :

CVE-2020-3350: Fix a vulnerability wherein a malicious user could
replace a scan target's directory with a symlink to another path to
trick clamscan, clamdscan, or clamonacc into removing or moving a
different file (eg. a critical system file). The issue would affect
users that use the --move or --remove options for clamscan, clamdscan,
and clamonacc. (bsc#1174255)

CVE-2020-3327: Fix a vulnerability in the ARJ archive parsing module
in ClamAV 0.102.3 that could cause a Denial-of-Service (DoS)
condition. Improper bounds checking results in an out-of-bounds read
which could cause a crash. The previous fix for this CVE in 0.102.3
was incomplete. This fix correctly resolves the issue.

CVE-2020-3481: Fix a vulnerability in the EGG archive module in ClamAV
0.102.0 - 0.102.3 could cause a Denial-of-Service (DoS) condition.
Improper error handling may result in a crash due to a NULL pointer
dereference. This vulnerability is mitigated for those using the
official ClamAV signature databases because the file type signatures
in daily.cvd will not enable the EGG archive parser in versions
affected by the vulnerability. (bsc#1174250)

CVE-2020-3341: Fix a vulnerability in the PDF parsing module in ClamAV
0.101 - 0.102.2 that could cause a Denial-of-Service (DoS) condition.
Improper size checking of a buffer used to initialize AES decryption
routines results in an out-of-bounds read which may cause a crash.
(bsc#1171981)

CVE-2020-3123: A denial-of-service (DoS) condition may occur when
using the optional credit card data-loss-prevention (DLP) feature.
Improper bounds checking of an unsigned variable resulted in an
out-of-bounds read, which causes a crash.

CVE-2019-15961: A Denial-of-Service (DoS) vulnerability may occur when
scanning a specially crafted email file as a result of excessively
long scan times. The issue is resolved by implementing several
maximums in parsing MIME messages and by optimizing use of memory
allocation. (bsc#1157763).

CVE-2019-12900: An out of bounds write in the NSIS bzip2 (bsc#1149458)

CVE-2019-12625: Introduce a configurable time limit to mitigate zip
bomb vulnerability completely. Default is 2 minutes, configurable
useing the clamscan --max-scantime and for clamd using the MaxScanTime
config option (bsc#1144504)

Increase the startup timeout of clamd to 5 minutes to cater for the
grown virus database as a workaround until clamd has learned to talk
to systemd to extend the timeout as long as needed. (bsc#1151839)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1118459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1119353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1144504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1149458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1151839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1171981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1174250"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1174255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-12625/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-12900/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-15961/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-3123/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-3327/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-3341/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-3350/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-3481/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20203729-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f6f4ad64"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-SP5 :

zypper in -t patch SUSE-SLE-SERVER-12-SP5-2020-3729=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:clamav-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:clamav-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"5", reference:"clamav-0.103.0-3.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"clamav-debuginfo-0.103.0-3.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"clamav-debugsource-0.103.0-3.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clamav");
}
