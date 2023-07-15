#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:3056-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(131306);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-10811", "CVE-2018-16151", "CVE-2018-16152", "CVE-2018-17540", "CVE-2018-5388");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : strongswan (SUSE-SU-2019:3056-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for strongswan fixes the following issues :

Security issues fixed :

CVE-2018-5388: Fixed a buffer underflow which may allow to a remote
attacker with local user credentials to resource exhaustion and denial
of service while reading from the socket (bsc#1094462).

CVE-2018-10811: Fixed a denial of service during the IKEv2 key
derivation if the openssl plugin is used in FIPS mode and HMAC-MD5 is
negotiated as PRF (bsc#1093536).

CVE-2018-16151,CVE-2018-16152: Fixed multiple flaws in the gmp plugin
which might lead to authorization bypass (bsc#1107874).

CVE-2018-17540: Fixed an improper input validation in gmp plugin
(bsc#1109845).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1093536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1094462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1107874"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1109845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10811/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16151/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16152/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-17540/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5388/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20193056-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5714a8bf"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Packagehub Subpackages 15:zypper in
-t patch SUSE-SLE-Module-Packagehub-Subpackages-15-2019-3056=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-3056=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-3056=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2019-3056=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-3056=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16152");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-ipsec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-ipsec-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-libs0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-libs0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-nm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-nm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/26");
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
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-debuginfo-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-debugsource-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-hmac-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-ipsec-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-ipsec-debuginfo-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-libs0-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-libs0-debuginfo-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-mysql-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-mysql-debuginfo-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-nm-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-nm-debuginfo-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-sqlite-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-sqlite-debuginfo-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"strongswan-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"strongswan-debuginfo-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"strongswan-debugsource-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"strongswan-hmac-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"strongswan-ipsec-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"strongswan-ipsec-debuginfo-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"strongswan-libs0-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"strongswan-libs0-debuginfo-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"strongswan-mysql-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"strongswan-mysql-debuginfo-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"strongswan-nm-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"strongswan-nm-debuginfo-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"strongswan-sqlite-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"strongswan-sqlite-debuginfo-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-debuginfo-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-debugsource-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-hmac-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-ipsec-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-ipsec-debuginfo-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-libs0-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-libs0-debuginfo-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-mysql-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-mysql-debuginfo-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-nm-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-nm-debuginfo-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-sqlite-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-sqlite-debuginfo-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"strongswan-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"strongswan-debuginfo-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"strongswan-debugsource-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"strongswan-hmac-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"strongswan-ipsec-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"strongswan-ipsec-debuginfo-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"strongswan-libs0-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"strongswan-libs0-debuginfo-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"strongswan-mysql-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"strongswan-mysql-debuginfo-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"strongswan-nm-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"strongswan-nm-debuginfo-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"strongswan-sqlite-5.6.0-4.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"strongswan-sqlite-debuginfo-5.6.0-4.3.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "strongswan");
}
