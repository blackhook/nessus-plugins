#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:3583. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130555);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/17");

  script_cve_id("CVE-2018-20534", "CVE-2019-3817");
  script_xref(name:"RHSA", value:"2019:3583");

  script_name(english:"RHEL 8 : yum (RHSA-2019:3583)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for yum is now available for Red Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Yum is a command-line utility that allows the user to check for
updates and automatically download and install updated RPM packages.
Yum automatically obtains and downloads dependencies, prompting the
user for permission as necessary.

The following packages have been upgraded to a later upstream version:
dnf (4.2.7), dnf-plugins-core (4.0.8), libcomps (0.1.11), libdnf
(0.35.1), librepo (1.10.3), libsolv (0.7.4). (BZ#1690288, BZ#1690289,
BZ#1690299, BZ#1692402, BZ# 1694019, BZ#1697946)

Security Fix(es) :

* libcomps: use after free when merging two objmrtrees (CVE-2019-3817)

* libsolv: illegal address access in pool_whatprovides in src/pool.h
(CVE-2018-20534)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 8.1 Release Notes linked from the References section."
  );
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?774148ae"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:3583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-20534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-3817"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:createrepo_c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:createrepo_c-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:createrepo_c-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:createrepo_c-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:createrepo_c-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:createrepo_c-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dnf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dnf-automatic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dnf-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dnf-plugins-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcomps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcomps-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcomps-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcomps-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdnf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdnf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdnf-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librepo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librepo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librepo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librhsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librhsm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librhsm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsolv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsolv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsolv-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsolv-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsolv-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:microdnf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:microdnf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:microdnf-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-createrepo_c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-createrepo_c-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-dnf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-dnf-plugin-versionlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-dnf-plugins-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-hawkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-hawkey-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-libcomps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-libcomps-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-libdnf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-libdnf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-librepo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-librepo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 8.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:3583";
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
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"createrepo_c-0.11.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"createrepo_c-0.11.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"createrepo_c-debuginfo-0.11.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"createrepo_c-debuginfo-0.11.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"createrepo_c-debuginfo-0.11.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"createrepo_c-debugsource-0.11.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"createrepo_c-debugsource-0.11.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"createrepo_c-debugsource-0.11.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"createrepo_c-devel-0.11.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"createrepo_c-devel-0.11.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"createrepo_c-devel-0.11.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"createrepo_c-libs-0.11.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"createrepo_c-libs-0.11.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"createrepo_c-libs-0.11.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"createrepo_c-libs-debuginfo-0.11.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"createrepo_c-libs-debuginfo-0.11.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"createrepo_c-libs-debuginfo-0.11.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"dnf-4.2.7-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"dnf-automatic-4.2.7-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"dnf-data-4.2.7-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"dnf-plugins-core-4.0.8-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libcomps-0.1.11-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libcomps-0.1.11-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libcomps-0.1.11-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libcomps-debuginfo-0.1.11-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libcomps-debuginfo-0.1.11-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libcomps-debuginfo-0.1.11-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libcomps-debugsource-0.1.11-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libcomps-debugsource-0.1.11-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libcomps-debugsource-0.1.11-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libcomps-devel-0.1.11-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libcomps-devel-0.1.11-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libcomps-devel-0.1.11-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libdnf-0.35.1-8.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libdnf-0.35.1-8.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libdnf-0.35.1-8.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libdnf-debuginfo-0.35.1-8.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libdnf-debuginfo-0.35.1-8.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libdnf-debuginfo-0.35.1-8.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libdnf-debugsource-0.35.1-8.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libdnf-debugsource-0.35.1-8.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libdnf-debugsource-0.35.1-8.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"librepo-1.10.3-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"librepo-1.10.3-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"librepo-1.10.3-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"librepo-debuginfo-1.10.3-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"librepo-debuginfo-1.10.3-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"librepo-debuginfo-1.10.3-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"librepo-debugsource-1.10.3-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"librepo-debugsource-1.10.3-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"librepo-debugsource-1.10.3-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"librhsm-0.0.3-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"librhsm-0.0.3-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"librhsm-0.0.3-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"librhsm-debuginfo-0.0.3-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"librhsm-debuginfo-0.0.3-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"librhsm-debuginfo-0.0.3-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"librhsm-debugsource-0.0.3-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"librhsm-debugsource-0.0.3-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"librhsm-debugsource-0.0.3-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libsolv-0.7.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libsolv-0.7.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libsolv-0.7.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libsolv-debuginfo-0.7.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libsolv-debuginfo-0.7.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libsolv-debuginfo-0.7.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libsolv-debugsource-0.7.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libsolv-debugsource-0.7.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libsolv-debugsource-0.7.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libsolv-demo-debuginfo-0.7.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libsolv-demo-debuginfo-0.7.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libsolv-demo-debuginfo-0.7.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libsolv-tools-debuginfo-0.7.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libsolv-tools-debuginfo-0.7.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libsolv-tools-debuginfo-0.7.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"microdnf-3.0.1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"microdnf-3.0.1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"microdnf-debuginfo-3.0.1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"microdnf-debuginfo-3.0.1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"microdnf-debugsource-3.0.1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"microdnf-debugsource-3.0.1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"perl-solv-debuginfo-0.7.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"perl-solv-debuginfo-0.7.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"perl-solv-debuginfo-0.7.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-createrepo_c-0.11.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-createrepo_c-0.11.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"python3-createrepo_c-debuginfo-0.11.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-createrepo_c-debuginfo-0.11.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-createrepo_c-debuginfo-0.11.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"python3-dnf-4.2.7-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"python3-dnf-plugin-versionlock-4.0.8-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"python3-dnf-plugins-core-4.0.8-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-hawkey-0.35.1-8.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-hawkey-0.35.1-8.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"python3-hawkey-debuginfo-0.35.1-8.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-hawkey-debuginfo-0.35.1-8.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-hawkey-debuginfo-0.35.1-8.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-libcomps-0.1.11-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-libcomps-0.1.11-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"python3-libcomps-debuginfo-0.1.11-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-libcomps-debuginfo-0.1.11-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-libcomps-debuginfo-0.1.11-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-libdnf-0.35.1-8.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-libdnf-0.35.1-8.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"python3-libdnf-debuginfo-0.35.1-8.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-libdnf-debuginfo-0.35.1-8.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-libdnf-debuginfo-0.35.1-8.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-librepo-1.10.3-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-librepo-1.10.3-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"python3-librepo-debuginfo-1.10.3-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-librepo-debuginfo-1.10.3-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-librepo-debuginfo-1.10.3-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"python3-solv-debuginfo-0.7.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-solv-debuginfo-0.7.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-solv-debuginfo-0.7.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"ruby-solv-debuginfo-0.7.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"ruby-solv-debuginfo-0.7.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"ruby-solv-debuginfo-0.7.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"yum-4.2.7-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"yum-utils-4.0.8-3.el8")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "createrepo_c / createrepo_c-debuginfo / createrepo_c-debugsource / etc");
  }
}
