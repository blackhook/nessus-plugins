#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2485. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102538);
  script_version("3.11");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2017-1000117");
  script_xref(name:"RHSA", value:"2017:2485");

  script_name(english:"RHEL 6 : git (RHSA-2017:2485)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for git is now available for Red Hat Enterprise Linux 6.

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
    value:"https://access.redhat.com/errata/RHSA-2017:2485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-1000117"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Malicious Git HTTP Server For CVE-2017-1000117');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:emacs-git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:emacs-git-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gitweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Git");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:2485";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", reference:"emacs-git-1.7.1-9.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", reference:"emacs-git-el-1.7.1-9.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"git-1.7.1-9.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"git-1.7.1-9.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"git-1.7.1-9.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", reference:"git-all-1.7.1-9.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", reference:"git-cvs-1.7.1-9.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"git-daemon-1.7.1-9.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"git-daemon-1.7.1-9.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"git-daemon-1.7.1-9.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"git-debuginfo-1.7.1-9.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"git-debuginfo-1.7.1-9.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"git-debuginfo-1.7.1-9.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", reference:"git-email-1.7.1-9.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", reference:"git-gui-1.7.1-9.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", reference:"git-svn-1.7.1-9.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", reference:"gitk-1.7.1-9.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", reference:"gitweb-1.7.1-9.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-Git-1.7.1-9.el6_9")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs-git / emacs-git-el / git / git-all / git-cvs / git-daemon / etc");
  }
}
