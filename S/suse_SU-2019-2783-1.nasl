#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2783-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(130343);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-12068", "CVE-2019-14378", "CVE-2019-15890", "CVE-2019-17340", "CVE-2019-17341", "CVE-2019-17342", "CVE-2019-17343", "CVE-2019-17344", "CVE-2019-17346", "CVE-2019-17347", "CVE-2019-17348");

  script_name(english:"SUSE SLES12 Security Update : xen (SUSE-SU-2019:2783-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for xen fixes the following issues :

CVE-2019-15890: Fixed a use-after-free in SLiRP networking
implementation of QEMU emulator which could have led to Denial of
Service (bsc#1149813).

CVE-2019-12068: Fixed an issue in lsi which could lead to an infinite
loop and denial of service (bsc#1146874).

CVE-2019-14378: Fixed a heap buffer overflow in SLiRp networking
implementation of QEMU emulator which could have led to execution of
arbitrary code with privileges of the QEMU process (bsc#1143797).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1126140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1126141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1126192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1126195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1126196"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1126198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1126201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1127400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1143797"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1146874"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1149813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-12068/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-14378/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-15890/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-17340/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-17341/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-17342/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-17343/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-17344/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-17346/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-17347/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-17348/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192783-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb6ba1ab"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2019-2783=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2019-2783=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2019-2783=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2019-2783=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2019-2783=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17346");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/28");
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
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"xen-4.7.6_06-43.54.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"xen-debugsource-4.7.6_06-43.54.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"xen-doc-html-4.7.6_06-43.54.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"xen-libs-32bit-4.7.6_06-43.54.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"xen-libs-4.7.6_06-43.54.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.7.6_06-43.54.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"xen-libs-debuginfo-4.7.6_06-43.54.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"xen-tools-4.7.6_06-43.54.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"xen-tools-debuginfo-4.7.6_06-43.54.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"xen-tools-domU-4.7.6_06-43.54.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"xen-tools-domU-debuginfo-4.7.6_06-43.54.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
