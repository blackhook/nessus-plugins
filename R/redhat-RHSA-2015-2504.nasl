#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2504. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87045);
  script_version("1.10");
  script_cvs_date("Date: 2019/10/24 15:35:40");

  script_cve_id("CVE-2015-5302");
  script_xref(name:"RHSA", value:"2015:2504");

  script_name(english:"RHEL 6 : libreport (RHSA-2015:2504)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libreport packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

libreport provides an API for reporting different problems in
applications to different bug targets, such as Bugzilla, FTP, and
Trac. ABRT (Automatic Bug Reporting Tool) uses libreport.

It was found that ABRT may have exposed unintended information to Red
Hat Bugzilla during crash reporting. A bug in the libreport library
caused changes made by a user in files included in a crash report to
be discarded. As a result, Red Hat Bugzilla attachments may contain
data that was not intended to be made public, including host names, IP
addresses, or command line options. (CVE-2015-5302)

This flaw did not affect default installations of ABRT on Red Hat
Enterprise Linux as they do not post data to Red Hat Bugzilla. This
feature can however be enabled, potentially impacting modified ABRT
instances.

As a precaution, Red Hat has identified bugs filed by such non-default
Red Hat Enterprise Linux users of ABRT and marked them private.

This issue was discovered by Bastien Nocera of Red Hat.

All users of libreport are advised to upgrade to these updated
packages, which corrects this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2015:2504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-5302"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-newt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-bugzilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-kerneloops");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-mailx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-reportuploader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-rhtsupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-ureport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2015:2504";
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
  if (rpm_check(release:"RHEL6", reference:"libreport-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-cli-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-cli-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-cli-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-compat-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-compat-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-compat-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libreport-debuginfo-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libreport-devel-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-filesystem-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-filesystem-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-filesystem-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libreport-gtk-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libreport-gtk-devel-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-newt-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-newt-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-newt-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-plugin-bugzilla-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-plugin-bugzilla-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-plugin-bugzilla-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-plugin-kerneloops-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-plugin-kerneloops-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-plugin-kerneloops-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-plugin-logger-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-plugin-logger-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-plugin-logger-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-plugin-mailx-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-plugin-mailx-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-plugin-mailx-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-plugin-reportuploader-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-plugin-reportuploader-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-plugin-reportuploader-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-plugin-rhtsupport-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-plugin-rhtsupport-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-plugin-rhtsupport-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-plugin-ureport-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-plugin-ureport-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-plugin-ureport-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-python-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-python-2.0.9-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-python-2.0.9-25.el6_7")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libreport / libreport-cli / libreport-compat / libreport-debuginfo / etc");
  }
}
