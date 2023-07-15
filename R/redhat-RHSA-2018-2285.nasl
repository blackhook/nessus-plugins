#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2285. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111490);
  script_version("1.7");
  script_cvs_date("Date: 2019/10/24 15:35:45");

  script_cve_id("CVE-2018-10897");
  script_xref(name:"RHSA", value:"2018:2285");

  script_name(english:"RHEL 7 : yum-utils (RHSA-2018:2285)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for yum-utils is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The yum-utils packages provide a collection of utilities and examples
for the yum package manager to make yum easier and more powerful to
use.

Security Fix(es) :

* yum-utils: reposync: improper path validation may lead to directory
traversal (CVE-2018-10897)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank Jay Grizzard (Clover Network) and Aaron
Levy (Clover Network) for reporting this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:2285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-10897"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-NetworkManager-dispatcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-aliases");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-auto-update-debug-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-changelog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-copr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-fastestmirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-filter-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-fs-snapshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-list-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-merge-conf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-ovl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-post-transaction-actions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-pre-transaction-actions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-priorities");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-protectbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-ps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-remove-with-leaves");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-rpm-warm-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-show-leaves");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-tmprepo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-tsflags");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-upgrade-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-verify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-versionlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-updateonboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/02");
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
  rhsa = "RHSA-2018:2285";
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
  if (rpm_check(release:"RHEL7", reference:"yum-NetworkManager-dispatcher-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-plugin-aliases-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-plugin-auto-update-debug-info-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-plugin-changelog-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-plugin-copr-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-plugin-fastestmirror-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-plugin-filter-data-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-plugin-fs-snapshot-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-plugin-keys-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-plugin-list-data-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-plugin-local-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-plugin-merge-conf-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-plugin-ovl-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-plugin-post-transaction-actions-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-plugin-pre-transaction-actions-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-plugin-priorities-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-plugin-protectbase-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-plugin-ps-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-plugin-remove-with-leaves-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-plugin-rpm-warm-cache-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-plugin-show-leaves-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-plugin-tmprepo-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-plugin-tsflags-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-plugin-upgrade-helper-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-plugin-verify-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-plugin-versionlock-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-updateonboot-1.1.31-46.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"yum-utils-1.1.31-46.el7_5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "yum-NetworkManager-dispatcher / yum-plugin-aliases / etc");
  }
}
