#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2168-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120002);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-1000381", "CVE-2017-11499");

  script_name(english:"SUSE SLES12 Security Update : nodejs4, nodejs6 (SUSE-SU-2017:2168-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for nodejs4 and nodejs6 fixes the following issues:
Security issues fixed :

  - CVE-2017-1000381: The c-ares function
    ares_parse_naptr_reply() could be triggered to read
    memory outside of the given input buffer if the passed
    in DNS response packet was crafted in a particular way.
    (bsc#1044946)

  - CVE-2017-11499: Disable V8 snapshots. The hashseed
    embedded in the snapshot is currently the same for all
    runs of the binary. This opens node up to collision
    attacks which could result in a Denial of Service. We
    have temporarily disabled snapshots until a more robust
    solution is found. (bsc#1048299) Non-security fixes :

  - GCC 7 compilation fixes for v8 backported and add
    missing ICU59 headers (bsc#1041282)

  - New upstream LTS release 6.11.1
    https://github.com/nodejs/node/blob/master/doc/changelog
    s/CHANGELOG_V6.md#6 .11.1

  - New upstream LTS release 6.11.0
    https://github.com/nodejs/node/blob/master/doc/changelog
    s/CHANGELOG_V6.md#6 .11.0

  - New upstream LTS release 6.10.3
    https://github.com/nodejs/node/blob/master/doc/changelog
    s/CHANGELOG_V6.md#6 .10.3

  - New upstream LTS release 6.10.2
    https://github.com/nodejs/node/blob/master/doc/changelog
    s/CHANGELOG_V6.md#6 .10.2

  - New upstream LTS release 6.10.1
    https://github.com/nodejs/node/blob/master/doc/changelog
    s/CHANGELOG_V6.md#6 .10.1

  - New upstream LTS release 6.10.0
    https://github.com/nodejs/node/blob/master/doc/changelog
    s/CHANGELOG_V6.md#6 .10.0

  - New upstream LTS release 4.8.4
    https://github.com/nodejs/node/blob/master/doc/changelog
    s/CHANGELOG_V4.md#4 .8.4

  - New upstream LTS release 4.8.3
    https://github.com/nodejs/node/blob/master/doc/changelog
    s/CHANGELOG_V4.md#4 .8.3

  - New upstream LTS release 4.8.2
    https://github.com/nodejs/node/blob/master/doc/changelog
    s/CHANGELOG_V4.md#4 .8.2

  - New upstream LTS release 4.8.1
    https://github.com/nodejs/node/blob/master/doc/changelog
    s/CHANGELOG_V4.md#4 .8.1

  - New upstream LTS release 4.8.0
    https://github.com/nodejs/node/blob/master/doc/changelog
    s/CHANGELOG_V4.md#4 .8.0

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1041282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1041283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1044946"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1048299"
  );
  # https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V4.md#4
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c242247b"
  );
  # https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V6.md#6
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?15cdcfe6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-1000381/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11499/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172168-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e75b1040"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2017-1331=1

SUSE Linux Enterprise Module for Web Scripting 12:zypper in -t patch
SUSE-SLE-Module-Web-Scripting-12-2017-1331=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2017-1331=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs4-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs6-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs6-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:npm4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:npm6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"nodejs4-4.8.4-15.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"nodejs4-debuginfo-4.8.4-15.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"nodejs4-debugsource-4.8.4-15.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"nodejs4-devel-4.8.4-15.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"npm4-4.8.4-15.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"nodejs6-6.11.1-11.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"nodejs6-debuginfo-6.11.1-11.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"nodejs6-debugsource-6.11.1-11.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"nodejs6-devel-6.11.1-11.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"npm6-6.11.1-11.5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nodejs4 / nodejs6");
}
