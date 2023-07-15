#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2388. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102118);
  script_version("3.16");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2017-1000083");
  script_xref(name:"RHSA", value:"2017:2388");

  script_name(english:"RHEL 7 : evince (RHSA-2017:2388)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for evince is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The evince packages provide a simple multi-page document viewer for
Portable Document Format (PDF), PostScript (PS), Encapsulated
PostScript (EPS) files, and, with additional back-ends, also the
Device Independent File format (DVI) files.

Security Fix(es) :

* It was found that evince did not properly sanitize the command line
which is run to untar Comic Book Tar (CBT) files, thereby allowing
command injection. A specially crafted CBT file, when opened by evince
or evince-thumbnailer, could execute arbitrary commands in the context
of the evince program. (CVE-2017-1000083)

Red Hat would like to thank Felix Wilhelm (Google Security Team) for
reporting this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:2388"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-1000083"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Evince CBT File Command Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evince-browser-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evince-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evince-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evince-dvi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evince-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evince-nautilus");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/02");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:2388";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"evince-3.22.1-5.2.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"evince-3.22.1-5.2.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"evince-browser-plugin-3.22.1-5.2.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"evince-browser-plugin-3.22.1-5.2.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", reference:"evince-debuginfo-3.22.1-5.2.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", reference:"evince-devel-3.22.1-5.2.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"evince-dvi-3.22.1-5.2.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"evince-dvi-3.22.1-5.2.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", reference:"evince-libs-3.22.1-5.2.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"evince-nautilus-3.22.1-5.2.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"evince-nautilus-3.22.1-5.2.el7_4")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "evince / evince-browser-plugin / evince-debuginfo / evince-devel / etc");
  }
}
