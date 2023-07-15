#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:1932. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110607);
  script_version("1.5");
  script_cvs_date("Date: 2019/10/24 15:35:45");

  script_cve_id("CVE-2014-10072", "CVE-2017-18206", "CVE-2018-1083", "CVE-2018-1100");
  script_xref(name:"RHSA", value:"2018:1932");

  script_name(english:"RHEL 6 : zsh (RHSA-2018:1932)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for zsh is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The zsh shell is a command interpreter usable as an interactive login
shell and as a shell script command processor. Zsh resembles the ksh
shell (the Korn shell), but includes many enhancements. Zsh supports
command-line editing, built-in spelling correction, programmable
command completion, shell functions (with autoloading), a history
mechanism, and more.

Security Fix(es) :

* zsh: Stack-based buffer overflow in gen_matches_files() at compctl.c
(CVE-2018-1083)

* zsh: buffer overflow when scanning very long directory paths for
symbolic links (CVE-2014-10072)

* zsh: buffer overrun in symlinks (CVE-2017-18206)

* zsh: buffer overflow in utils.c:checkmailpath() can lead to local
arbitrary code execution (CVE-2018-1100)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

The CVE-2018-1083 and CVE-2018-1100 issues were discovered by Richard
Maciel Costa (Red Hat).

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 6.10 Release Notes and Red Hat Enterprise Linux 6.10
Technical Notes linked from the References section."
  );
  # https://access.redhat.com/documentation/en-US/red_hat_enterprise_linux/6/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d2572ef"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:1932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-10072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-18206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1100"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected zsh, zsh-debuginfo and / or zsh-html packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:zsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:zsh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:zsh-html");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2018:1932";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"zsh-4.3.11-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"zsh-4.3.11-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"zsh-4.3.11-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"zsh-debuginfo-4.3.11-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"zsh-debuginfo-4.3.11-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"zsh-debuginfo-4.3.11-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"zsh-html-4.3.11-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"zsh-html-4.3.11-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"zsh-html-4.3.11-8.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "zsh / zsh-debuginfo / zsh-html");
  }
}
