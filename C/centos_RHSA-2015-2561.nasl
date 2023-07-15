#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2561 and 
# CentOS Errata and Security Advisory 2015:2561 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87282);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-7545");
  script_xref(name:"RHSA", value:"2015:2561");

  script_name(english:"CentOS 7 : git (CESA-2015:2561)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated git packages that fix one security issue are now available for
Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Git is a distributed revision control system with a decentralized
architecture. As opposed to centralized version control systems with a
client-server model, Git ensures that each working copy of a Git
repository is an exact copy with complete revision history. This not
only allows the user to work on and contribute to projects without the
need to have permission to push the changes to their official
repositories, but also makes it possible for the user to work with no
network connection.

A flaw was found in the way the git-remote-ext helper processed
certain URLs. If a user had Git configured to automatically clone
submodules from untrusted repositories, an attacker could inject
commands into the URL of a submodule, allowing them to execute
arbitrary code on the user's system. (BZ#1269794)

All git users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2015-December/002733.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?660f31dd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected git packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7545");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"emacs-git-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"emacs-git-el-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-all-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-bzr-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-cvs-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-daemon-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-email-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-gui-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-hg-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-p4-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-svn-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gitk-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gitweb-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-Git-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-Git-SVN-1.8.3.1-6.el7")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs-git / emacs-git-el / git / git-all / git-bzr / git-cvs / etc");
}
