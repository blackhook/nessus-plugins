#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:635. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15945);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2004-0983");
  script_xref(name:"RHSA", value:"2004:635");

  script_name(english:"RHEL 2.1 / 3 : ruby (RHSA-2004:635)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated ruby package that fixes a denial of service issue for the
CGI instance is now available.

[Updated 17 Jan 2005] Errata has been updated to include 32-bit
libraries on 64-bit architectures.

Ruby is an interpreted scripting language for object-oriented
programming.

A flaw was dicovered in the CGI module of Ruby. If empty data is sent
by the POST method to the CGI script which requires MIME type
multipart/form-data, it can get stuck in a loop. A remote attacker
could trigger this flaw and cause a denial of service. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2004-0983 to this issue.

Users are advised to upgrade to this erratum package, which contains a
backported patch to cgi.rb."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-0983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2004:635"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(2\.1|3)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2004:635";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"irb-1.6.4-2.AS21.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"ruby-1.6.4-2.AS21.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"ruby-devel-1.6.4-2.AS21.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"ruby-docs-1.6.4-2.AS21.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"ruby-libs-1.6.4-2.AS21.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"ruby-tcltk-1.6.4-2.AS21.1")) flag++;

  if (rpm_check(release:"RHEL3", reference:"irb-1.6.8-9.EL3.3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"ruby-1.6.8-9.EL3.3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"ruby-devel-1.6.8-9.EL3.3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"ruby-docs-1.6.8-9.EL3.3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"ruby-libs-1.6.8-9.EL3.3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"ruby-mode-1.6.8-9.EL3.3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"ruby-tcltk-1.6.8-9.EL3.3")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "irb / ruby / ruby-devel / ruby-docs / ruby-libs / ruby-mode / etc");
  }
}
