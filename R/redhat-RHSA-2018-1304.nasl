#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:1304. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109569);
  script_version("1.7");
  script_cvs_date("Date: 2019/10/24 15:35:44");

  script_cve_id("CVE-2018-6574");
  script_xref(name:"RHSA", value:"2018:1304");

  script_name(english:"RHEL 7 : go-toolset-7 and go-toolset-7-golang (RHSA-2018:1304)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for go-toolset-7 and go-toolset-7-golang is now available
for Red Hat Developer Tools.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Go Toolset provides the Go programming language tools and libraries.
Go is alternatively known as golang.

The following packages have been upgraded to a later upstream version:
go-toolset-7-golang (1.8.7). (BZ#1545319)

Go Toolset is provided as a Technology Preview.

Security Fix(es) :

* golang: arbitrary code execution during 'go get' via C compiler
options (CVE-2018-6574)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Additional Changes :

For detailed changes and information on usage, see Using Go Toolset
linked from the References section. For information on scope of
support, see the Technology Preview Features Support Scope document."
  );
  # https://access.redhat.com/documentation/en-us/red_hat_developer_tools/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d2aa056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/support/offerings/techpreview/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:1304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6574"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:go-toolset-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:go-toolset-7-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:go-toolset-7-golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:go-toolset-7-golang-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:go-toolset-7-golang-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:go-toolset-7-golang-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:go-toolset-7-golang-race");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:go-toolset-7-golang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:go-toolset-7-golang-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:go-toolset-7-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:go-toolset-7-scldevel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/04");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:1304";
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
  if (rpm_check(release:"RHEL7", cpu:"aarch64", reference:"go-toolset-7-1.8-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"go-toolset-7-1.8-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"go-toolset-7-1.8-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"aarch64", reference:"go-toolset-7-build-1.8-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"go-toolset-7-build-1.8-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"go-toolset-7-build-1.8-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"aarch64", reference:"go-toolset-7-golang-1.8.7-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"go-toolset-7-golang-1.8.7-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"go-toolset-7-golang-1.8.7-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"aarch64", reference:"go-toolset-7-golang-bin-1.8.7-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"go-toolset-7-golang-bin-1.8.7-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"go-toolset-7-golang-bin-1.8.7-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"go-toolset-7-golang-docs-1.8.7-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"go-toolset-7-golang-misc-1.8.7-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"go-toolset-7-golang-race-1.8.7-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"go-toolset-7-golang-src-1.8.7-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"go-toolset-7-golang-tests-1.8.7-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"aarch64", reference:"go-toolset-7-runtime-1.8-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"go-toolset-7-runtime-1.8-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"go-toolset-7-runtime-1.8-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"aarch64", reference:"go-toolset-7-scldevel-1.8-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"go-toolset-7-scldevel-1.8-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"go-toolset-7-scldevel-1.8-14.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "go-toolset-7 / go-toolset-7-build / go-toolset-7-golang / etc");
  }
}
