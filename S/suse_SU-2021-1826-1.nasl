#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:1826-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(150215);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/07");

  script_cve_id("CVE-2021-25214", "CVE-2021-25215");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : bind (SUSE-SU-2021:1826-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for bind fixes the following issues :

CVE-2021-25214: Fixed a broken inbound incremental zone update (IXFR)
which could have caused named to terminate unexpectedly (bsc#1185345).

CVE-2021-25215: Fixed an assertion check which could have failed while
answering queries for DNAME records that required the DNAME to be
processed to resolve itself (bsc#1185345).

Switched from /var/run to /run (bsc#1185073)

Hardening: Compiled binary with PIE flags to make it position
independent

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1183453"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1185073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-25214/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-25215/"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20211826-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a62e9bdf"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Server Applications 15-SP3 :

zypper in -t patch
SUSE-SLE-Module-Server-Applications-15-SP3-2021-1826=1

SUSE Linux Enterprise Module for Basesystem 15-SP3 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP3-2021-1826=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-chrootenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libbind9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libbind9-1600-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdns1605");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdns1605-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libirs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libirs1601");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libirs1601-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libisc1606");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libisc1606-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libisccc1600");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libisccc1600-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libisccfg1600");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libisccfg1600-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libns1604");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libns1604-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/03");
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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"3", reference:"bind-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"bind-chrootenv-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"bind-debuginfo-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"bind-debugsource-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"bind-devel-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"bind-utils-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"bind-utils-debuginfo-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libbind9-1600-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libbind9-1600-debuginfo-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libdns1605-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libdns1605-debuginfo-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libirs-devel-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libirs1601-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libirs1601-debuginfo-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libisc1606-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libisc1606-debuginfo-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libisccc1600-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libisccc1600-debuginfo-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libisccfg1600-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libisccfg1600-debuginfo-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libns1604-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libns1604-debuginfo-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"bind-debuginfo-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"bind-debugsource-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"bind-devel-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"bind-utils-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"bind-utils-debuginfo-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libbind9-1600-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libbind9-1600-debuginfo-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libdns1605-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libdns1605-debuginfo-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libirs-devel-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libirs1601-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libirs1601-debuginfo-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libisc1606-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libisc1606-debuginfo-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libisccc1600-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libisccc1600-debuginfo-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libisccfg1600-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libisccfg1600-debuginfo-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libns1604-9.16.6-22.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libns1604-debuginfo-9.16.6-22.7.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind");
}
