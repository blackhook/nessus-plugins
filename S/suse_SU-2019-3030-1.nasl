#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:3030-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(131221);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/29");

  script_cve_id("CVE-2019-8675", "CVE-2019-8696");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : cups (SUSE-SU-2019:3030-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for cups fixes the following issues :

CVE-2019-8675: Fixed a stack-based buffer overflow in libcups's
asn1_get_type function(bsc#1146358).

CVE-2019-8696: Fixed a stack-based buffer overflow in libcups's
asn1_get_packed function (bsc#1146359).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1146358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1146359"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8675/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8696/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20193030-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9a98ed2e"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-3030=1

SUSE Linux Enterprise Module for Development Tools 15-SP1:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-SP1-2019-3030=1

SUSE Linux Enterprise Module for Development Tools 15:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-2019-3030=1

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2019-3030=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2019-3030=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-3030=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-ddk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-ddk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcups2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcups2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcups2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcupscgi1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcupscgi1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcupscgi1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcupsimage2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcupsimage2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcupsimage2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcupsmime1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcupsmime1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcupsmime1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcupsppdc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcupsppdc1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcupsppdc1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/22");
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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"cups-devel-32bit-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libcups2-32bit-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libcups2-32bit-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libcupscgi1-32bit-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libcupscgi1-32bit-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libcupsimage2-32bit-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libcupsimage2-32bit-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libcupsmime1-32bit-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libcupsmime1-32bit-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libcupsppdc1-32bit-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libcupsppdc1-32bit-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cups-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cups-client-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cups-client-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cups-config-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cups-ddk-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cups-ddk-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cups-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cups-debugsource-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cups-devel-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libcups2-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libcups2-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libcupscgi1-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libcupscgi1-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libcupsimage2-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libcupsimage2-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libcupsmime1-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libcupsmime1-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libcupsppdc1-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libcupsppdc1-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libcups2-32bit-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libcups2-32bit-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cups-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cups-client-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cups-client-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cups-config-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cups-ddk-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cups-ddk-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cups-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cups-debugsource-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cups-devel-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcups2-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcups2-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcupscgi1-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcupscgi1-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcupsimage2-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcupsimage2-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcupsmime1-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcupsmime1-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcupsppdc1-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcupsppdc1-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"cups-devel-32bit-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libcups2-32bit-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libcups2-32bit-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libcupscgi1-32bit-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libcupscgi1-32bit-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libcupsimage2-32bit-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libcupsimage2-32bit-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libcupsmime1-32bit-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libcupsmime1-32bit-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libcupsppdc1-32bit-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libcupsppdc1-32bit-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cups-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cups-client-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cups-client-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cups-config-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cups-ddk-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cups-ddk-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cups-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cups-debugsource-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cups-devel-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libcups2-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libcups2-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libcupscgi1-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libcupscgi1-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libcupsimage2-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libcupsimage2-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libcupsmime1-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libcupsmime1-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libcupsppdc1-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libcupsppdc1-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libcups2-32bit-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libcups2-32bit-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cups-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cups-client-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cups-client-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cups-config-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cups-ddk-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cups-ddk-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cups-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cups-debugsource-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cups-devel-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcups2-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcups2-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcupscgi1-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcupscgi1-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcupsimage2-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcupsimage2-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcupsmime1-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcupsmime1-debuginfo-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcupsppdc1-2.2.7-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcupsppdc1-debuginfo-2.2.7-3.14.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups");
}
