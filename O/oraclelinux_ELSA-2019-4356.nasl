#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:4356 and 
# Oracle Linux Security Advisory ELSA-2019-4356 respectively.
#

include("compat.inc");

if (description)
{
  script_id(132381);
  script_version("1.4");
  script_cvs_date("Date: 2020/01/30");

  script_cve_id("CVE-2019-1348", "CVE-2019-1349", "CVE-2019-1352", "CVE-2019-1387");
  script_xref(name:"RHSA", value:"2019:4356");

  script_name(english:"Oracle Linux 8 : git (ELSA-2019-4356)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2019:4356 :

An update for git is now available for Red Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Git is a distributed revision control system with a decentralized
architecture. As opposed to centralized version control systems with a
client-server model, Git ensures that each working copy of a Git
repository is an exact copy with complete revision history. This not
only allows the user to work on and contribute to projects without the
need to have permission to push the changes to their official
repositories, but also makes it possible for the user to work with no
network connection.

The following packages have been upgraded to a later upstream version:
git (2.18.2). (BZ#1784058)

Security Fix(es) :

* git: Remote code execution in recursive clones with nested
submodules (CVE-2019-1387)

* git: Arbitrary path overwriting via export-marks in-stream command
feature (CVE-2019-1348)

* git: Recursive submodule cloning allows using git directory twice
with synonymous directory name written in .git/ (CVE-2019-1349)

* git: Files inside the .git directory may be overwritten during
cloning via NTFS Alternate Data Streams (CVE-2019-1352)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-December/009484.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected git packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1352");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-core-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-instaweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-subtree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gitweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Git-SVN");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 8", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"git-2.18.2-1.el8_1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"git-all-2.18.2-1.el8_1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"git-core-2.18.2-1.el8_1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"git-core-doc-2.18.2-1.el8_1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"git-daemon-2.18.2-1.el8_1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"git-email-2.18.2-1.el8_1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"git-gui-2.18.2-1.el8_1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"git-instaweb-2.18.2-1.el8_1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"git-subtree-2.18.2-1.el8_1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"git-svn-2.18.2-1.el8_1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"gitk-2.18.2-1.el8_1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"gitweb-2.18.2-1.el8_1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"perl-Git-2.18.2-1.el8_1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"perl-Git-SVN-2.18.2-1.el8_1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "git / git-all / git-core / git-core-doc / git-daemon / git-email / etc");
}
