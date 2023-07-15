#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0129-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(145026);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/20");

  script_cve_id("CVE-2020-25709", "CVE-2020-25710");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : openldap2 (SUSE-SU-2021:0129-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for openldap2 fixes the following issues :

Security issues fixed :

CVE-2020-25709: Fixed a crash caused by specially crafted network
traffic (bsc#1178909).

CVE-2020-25710: Fixed a crash caused by specially crafted network
traffic (bsc#1178909).

Non-security issue fixed :

Retry binds in the LDAP backend when the remote LDAP server
disconnected the (idle) LDAP connection. (bsc#1179503)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-25709/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-25710/"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210129-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74851412"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Legacy Software 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Legacy-15-SP2-2021-129=1

SUSE Linux Enterprise Module for Development Tools 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Development-Tools-15-SP2-2021-129=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2021-129=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25710");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldap-2_4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldap-2_4-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldap-2_4-2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldap-2_4-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-back-meta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-back-meta-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-back-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-back-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-ppolicy-check-password");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openldap2-ppolicy-check-password-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/15");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libldap-2_4-2-32bit-2.4.46-9.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libldap-2_4-2-32bit-debuginfo-2.4.46-9.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"openldap2-devel-32bit-2.4.46-9.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libldap-2_4-2-2.4.46-9.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libldap-2_4-2-debuginfo-2.4.46-9.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openldap2-2.4.46-9.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openldap2-back-meta-2.4.46-9.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openldap2-back-meta-debuginfo-2.4.46-9.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openldap2-back-perl-2.4.46-9.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openldap2-back-perl-debuginfo-2.4.46-9.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openldap2-client-2.4.46-9.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openldap2-client-debuginfo-2.4.46-9.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openldap2-debuginfo-2.4.46-9.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openldap2-debugsource-2.4.46-9.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openldap2-devel-2.4.46-9.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openldap2-devel-static-2.4.46-9.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openldap2-ppolicy-check-password-1.2-9.45.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openldap2-ppolicy-check-password-debuginfo-1.2-9.45.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libldap-2_4-2-32bit-2.4.46-9.45.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libldap-2_4-2-32bit-debuginfo-2.4.46-9.45.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"openldap2-devel-32bit-2.4.46-9.45.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libldap-2_4-2-2.4.46-9.45.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libldap-2_4-2-debuginfo-2.4.46-9.45.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"openldap2-client-2.4.46-9.45.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"openldap2-client-debuginfo-2.4.46-9.45.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"openldap2-debugsource-2.4.46-9.45.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"openldap2-devel-2.4.46-9.45.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"openldap2-devel-static-2.4.46-9.45.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openldap2");
}
