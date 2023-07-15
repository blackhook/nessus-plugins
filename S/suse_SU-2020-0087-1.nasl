#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0087-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(132923);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-18900");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : libsolv, libzypp, zypper (SUSE-SU-2020:0087-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libsolv, libzypp, zypper fixes the following issues :

Security issue fixed :

CVE-2019-18900: Fixed assert cookie file that was world readable
(bsc#1158763).

Bug fixes Fixed removing orphaned packages dropped by to-be-installed
products (bsc#1155819).

Adds libzypp API to mark all obsolete kernels according to the
existing purge-kernel script rules (bsc#1155198).

Do not enforce 'en' being in RequestedLocales If the user decides to
have a system without explicit language support he may do so
(bsc#1155678).

Load only target resolvables for zypper rm (bsc#1157377).

Fix broken search by filelist (bsc#1135114).

Replace python by a bash script in zypper-log (fixes#304, fixes#306,
bsc#1156158).

Do not sort out requested locales which are not available
(bsc#1155678).

Prevent listing duplicate matches in tables. XML result is provided
within the new list-patches-byissue element (bsc#1154805).

XML add patch issue-date and issue-list (bsc#1154805).

Fix zypper lp --cve/bugzilla/issue options (bsc#1155298).

Always execute commit when adding/removing locales (fixes
bsc#1155205).

Fix description of --table-style,-s in man page (bsc#1154804).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1135114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1155198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1155205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1155298"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1155678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1155819"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1156158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-18900/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200087-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f69a5ec"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-87=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2020-87=1

SUSE Linux Enterprise Module for Development Tools 15:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-2020-87=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2020-87=1

SUSE Linux Enterprise Installer 15:zypper in -t patch
SUSE-SLE-INSTALLER-15-2020-87=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp-devel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:zypper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:zypper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:zypper-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/15");
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
if (os_ver == "SLED15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-solv-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-solv-debuginfo-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsolv-debuginfo-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsolv-debugsource-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsolv-demo-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsolv-demo-debuginfo-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsolv-devel-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsolv-devel-debuginfo-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsolv-tools-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsolv-tools-debuginfo-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libzypp-17.19.0-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libzypp-debuginfo-17.19.0-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libzypp-debugsource-17.19.0-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libzypp-devel-17.19.0-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libzypp-devel-doc-17.19.0-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"perl-solv-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"perl-solv-debuginfo-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-solv-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-solv-debuginfo-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-solv-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-solv-debuginfo-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ruby-solv-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ruby-solv-debuginfo-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"zypper-1.14.33-3.29.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"zypper-debuginfo-1.14.33-3.29.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"zypper-debugsource-1.14.33-3.29.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python-solv-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python-solv-debuginfo-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsolv-debuginfo-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsolv-debugsource-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsolv-demo-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsolv-demo-debuginfo-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsolv-devel-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsolv-devel-debuginfo-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsolv-tools-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsolv-tools-debuginfo-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libzypp-17.19.0-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libzypp-debuginfo-17.19.0-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libzypp-debugsource-17.19.0-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libzypp-devel-17.19.0-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libzypp-devel-doc-17.19.0-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"perl-solv-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"perl-solv-debuginfo-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-solv-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-solv-debuginfo-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-solv-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-solv-debuginfo-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ruby-solv-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ruby-solv-debuginfo-0.7.10-3.22.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"zypper-1.14.33-3.29.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"zypper-debuginfo-1.14.33-3.29.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"zypper-debugsource-1.14.33-3.29.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsolv / libzypp / zypper");
}
