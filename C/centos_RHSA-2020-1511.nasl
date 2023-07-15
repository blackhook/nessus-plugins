#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2020:1511 and 
# CentOS Errata and Security Advisory 2020:1511 respectively.
#

include("compat.inc");

if (description)
{
  script_id(136197);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/05");

  script_cve_id("CVE-2020-5260");
  script_xref(name:"RHSA", value:"2020:1511");

  script_name(english:"CentOS 7 : git (CESA-2020:1511)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2020:1511 advisory.

  - git: Crafted URL containing new lines can cause
    credential leak (CVE-2020-5260)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number."
  );
  # https://lists.centos.org/pipermail/centos-announce/2020-April/035708.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?89325e66"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected git packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5260");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:git-gnome-keyring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:git-hg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:git-instaweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:git-p4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gitweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-Git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-Git-SVN");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"emacs-git-1.8.3.1-22.el7_8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"emacs-git-el-1.8.3.1-22.el7_8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-1.8.3.1-22.el7_8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-all-1.8.3.1-22.el7_8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-bzr-1.8.3.1-22.el7_8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-cvs-1.8.3.1-22.el7_8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-daemon-1.8.3.1-22.el7_8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-email-1.8.3.1-22.el7_8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-gnome-keyring-1.8.3.1-22.el7_8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-gui-1.8.3.1-22.el7_8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-hg-1.8.3.1-22.el7_8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-instaweb-1.8.3.1-22.el7_8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-p4-1.8.3.1-22.el7_8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"git-svn-1.8.3.1-22.el7_8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gitk-1.8.3.1-22.el7_8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gitweb-1.8.3.1-22.el7_8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-Git-1.8.3.1-22.el7_8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-Git-SVN-1.8.3.1-22.el7_8")) flag++;


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
