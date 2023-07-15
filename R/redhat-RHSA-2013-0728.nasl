#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0728. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119438);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-0256");
  script_bugtraq_id(57785);
  script_xref(name:"RHSA", value:"2013:0728");

  script_name(english:"RHEL 6 : rubygem packages (RHSA-2013:0728)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes one security issue in multiple rubygem packages for
Red Hat OpenShift Enterprise 1.1.3.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Ruby is an extensible, interpreted, object-oriented, scripting
language. It has features to process text files and to do system
management tasks.

It was found that documentation created by RDoc was vulnerable to a
cross-site scripting (XSS) attack. If such documentation was
accessible over a network, and a remote attacker could trick a user
into visiting a specially crafted URL, it would lead to arbitrary web
script execution in the context of the user's session. As RDoc is used
for creating documentation for Ruby source files (such as classes,
modules, and so on), it is not a common scenario to make such
documentation accessible over the network. (CVE-2013-0256)

This update provides a number of updated rubygem packages that have
had their documentation regenerated with a corrected version of RDoc.

Red Hat would like to thank Eric Hodel of RDoc upstream for reporting
this issue. Upstream acknowledges Evgeny Ermakov as the original
reporter.

Users of Red Hat OpenShift Enterprise 1.1.3 are advised to upgrade to
these updated packages, which correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2013:0728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-0256"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-activesupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-bcrypt-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-bcrypt-ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-chunky_png");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ci_reporter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-compass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-fastthread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-fastthread-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-haml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-http_connection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rack-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rspec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-treetop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-xml-simple");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2013:0728";
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
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-activesupport-3.2.8-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-bcrypt-ruby-3.0.1-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-bcrypt-ruby-debuginfo-3.0.1-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-bson-1.5.2-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-chunky_png-1.2.6-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-ci_reporter-1.7.2-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-compass-0.12.2-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-fastthread-1.0.7-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-fastthread-debuginfo-1.0.7-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-haml-3.1.7-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-http_connection-1.4.1-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-rack-1.4.1-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-rack-test-0.6.1-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-rspec-2.11.0-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-treetop-1.4.10-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-xml-simple-1.0.12-10.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby193-rubygem-activesupport / ruby193-rubygem-bcrypt-ruby / etc");
  }
}
