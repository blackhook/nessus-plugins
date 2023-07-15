#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:1957 and 
# CentOS Errata and Security Advisory 2018:1957 respectively.
#

include("compat.inc");

if (description)
{
  script_id(110663);
  script_version("1.7");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2018-11235");
  script_xref(name:"RHSA", value:"2018:1957");

  script_name(english:"CentOS 7 : git (CESA-2018:1957)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for git is now available for Red Hat Enterprise Linux 7.

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

* git: arbitrary code execution when recursively cloning a malicious
repository (CVE-2018-11235)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section."
  );
  # https://lists.centos.org/pipermail/centos-announce/2018-June/022924.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3090cd26"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected git packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11235");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs-git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs-git-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:git-bzr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:git-hg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:git-p4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gitweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-Git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-Git-SVN");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"emacs-git-1.8.3.1-14.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"emacs-git-el-1.8.3.1-14.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-1.8.3.1-14.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-all-1.8.3.1-14.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-bzr-1.8.3.1-14.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-cvs-1.8.3.1-14.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-daemon-1.8.3.1-14.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-email-1.8.3.1-14.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-gui-1.8.3.1-14.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-hg-1.8.3.1-14.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-p4-1.8.3.1-14.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-svn-1.8.3.1-14.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gitk-1.8.3.1-14.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gitweb-1.8.3.1-14.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-Git-1.8.3.1-14.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-Git-SVN-1.8.3.1-14.el7_5")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs-git / emacs-git-el / git / git-all / git-bzr / git-cvs / etc");
}
