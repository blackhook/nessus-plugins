#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:4001-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(120180);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-0734", "CVE-2018-5407");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : openssl-1_0_0 (SUSE-SU-2018:4001-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for openssl-1_0_0 fixes the following issues :

Security issues fixed :

CVE-2018-0734: Fixed timing vulnerability in DSA signature generation
(bsc#1113652).

CVE-2018-5407: Added elliptic curve scalar multiplication timing
attack defenses that fixes 'PortSmash' (bsc#1113534).

Non-security issues fixed: Added missing timing side channel patch for
DSA signature generation (bsc#1113742).

Set TLS version to 0 in msg_callback for record messages to avoid
confusing applications (bsc#1100078).

Fixed infinite loop in DSA generation with incorrect parameters
(bsc#1112209)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1100078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1113534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1113652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1113742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-0734/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5407/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20184001-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?95a56534"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2018-2862=1

SUSE Linux Enterprise Module for Legacy Software 15:zypper in -t patch
SUSE-SLE-Module-Legacy-15-2018-2862=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl-1_0_0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0-steam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0-steam-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-1_0_0-cavs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-1_0_0-cavs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-1_0_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-1_0_0-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/06");
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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", reference:"libopenssl-1_0_0-devel-1.0.2p-3.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libopenssl1_0_0-1.0.2p-3.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libopenssl1_0_0-debuginfo-1.0.2p-3.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libopenssl1_0_0-hmac-1.0.2p-3.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libopenssl1_0_0-steam-1.0.2p-3.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libopenssl1_0_0-steam-debuginfo-1.0.2p-3.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"openssl-1_0_0-1.0.2p-3.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"openssl-1_0_0-cavs-1.0.2p-3.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"openssl-1_0_0-cavs-debuginfo-1.0.2p-3.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"openssl-1_0_0-debuginfo-1.0.2p-3.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"openssl-1_0_0-debugsource-1.0.2p-3.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libopenssl1_0_0-hmac-1.0.2p-3.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libopenssl1_0_0-steam-1.0.2p-3.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libopenssl1_0_0-steam-debuginfo-1.0.2p-3.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"openssl-1_0_0-cavs-1.0.2p-3.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"openssl-1_0_0-cavs-debuginfo-1.0.2p-3.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"openssl-1_0_0-debuginfo-1.0.2p-3.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"openssl-1_0_0-debugsource-1.0.2p-3.11.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl-1_0_0");
}
