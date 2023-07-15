#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2017:2484 and 
# Oracle Linux Security Advisory ELSA-2017-2484 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102534);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-1000117");
  script_xref(name:"RHSA", value:"2017:2484");

  script_name(english:"Oracle Linux 7 : git (ELSA-2017-2484)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2017:2484 :

An update for git is now available for Red Hat Enterprise Linux 7.

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

Security Fix(es) :

* A shell command injection flaw related to the handling of 'ssh' URLs
has been discovered in Git. An attacker could use this flaw to execute
shell commands with the privileges of the user running the Git client,
for example, when performing a 'clone' action on a malicious
repository or a legitimate repository containing a malicious commit.
(CVE-2017-1000117)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-August/007133.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected git packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Malicious Git HTTP Server For CVE-2017-1000117');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:emacs-git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:emacs-git-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-bzr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-hg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-p4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gitweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Git-SVN");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"emacs-git-1.8.3.1-12.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"emacs-git-el-1.8.3.1-12.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"git-1.8.3.1-12.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"git-all-1.8.3.1-12.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"git-bzr-1.8.3.1-12.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"git-cvs-1.8.3.1-12.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"git-daemon-1.8.3.1-12.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"git-email-1.8.3.1-12.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"git-gui-1.8.3.1-12.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"git-hg-1.8.3.1-12.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"git-p4-1.8.3.1-12.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"git-svn-1.8.3.1-12.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gitk-1.8.3.1-12.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gitweb-1.8.3.1-12.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"perl-Git-1.8.3.1-12.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"perl-Git-SVN-1.8.3.1-12.el7_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs-git / emacs-git-el / git / git-all / git-bzr / git-cvs / etc");
}
