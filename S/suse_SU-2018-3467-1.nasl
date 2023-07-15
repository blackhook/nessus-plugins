#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:3467-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(118459);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/02");

  script_cve_id("CVE-2018-12472");

  script_name(english:"SUSE SLES12 Security Update : smt (SUSE-SU-2018:3467-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"SMT was updated to version 3.0.38.

Following security issue was fixed :

CVE-2018-12472: Harden hostname check during sibling check by forcing
double reverse lookup (bsc#1104076)

Following non security issues were fixed: Add migration path check
when registration sharing is enabled

Fix sibling sync errors (bsc#1111056) :

  - Synchronize all registered products

  - Handle duplicate registrations when syncing

  - Force resync to the sibling instance in `upgrade` and
    `synchronize` API calls

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104076"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1111056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12472/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20183467-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5afb150"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2018-2481=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2018-2481=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-2481=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-2481=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2018-2481=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2018-2481=1

SUSE Linux Enterprise Module for Public Cloud 12:zypper in -t patch
SUSE-SLE-Module-Public-Cloud-12-2018-2481=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2018-2481=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12472");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:res-signingkeys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:smt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:smt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:smt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:smt-support");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(1|2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1/2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"res-signingkeys-3.0.38-52.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"smt-3.0.38-52.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"smt-debuginfo-3.0.38-52.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"smt-debugsource-3.0.38-52.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"smt-support-3.0.38-52.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"res-signingkeys-3.0.38-52.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"smt-3.0.38-52.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"smt-debuginfo-3.0.38-52.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"smt-debugsource-3.0.38-52.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"smt-support-3.0.38-52.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"res-signingkeys-3.0.38-52.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"smt-3.0.38-52.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"smt-debuginfo-3.0.38-52.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"smt-debugsource-3.0.38-52.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"smt-support-3.0.38-52.26.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "smt");
}
