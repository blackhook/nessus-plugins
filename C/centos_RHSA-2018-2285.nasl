#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2285 and 
# CentOS Errata and Security Advisory 2018:2285 respectively.
#

include("compat.inc");

if (description)
{
  script_id(111615);
  script_version("1.5");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2018-10897");
  script_xref(name:"RHSA", value:"2018:2285");

  script_name(english:"CentOS 7 : yum-utils (CESA-2018:2285)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
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
  # https://lists.centos.org/pipermail/centos-announce/2018-August/022981.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6703a2ed"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected yum-utils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10897");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-NetworkManager-dispatcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-plugin-aliases");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-plugin-auto-update-debug-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-plugin-changelog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-plugin-copr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-plugin-fastestmirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-plugin-filter-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-plugin-fs-snapshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-plugin-keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-plugin-list-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-plugin-local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-plugin-merge-conf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-plugin-ovl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-plugin-post-transaction-actions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-plugin-pre-transaction-actions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-plugin-priorities");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-plugin-protectbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-plugin-ps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-plugin-remove-with-leaves");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-plugin-rpm-warm-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-plugin-show-leaves");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-plugin-tmprepo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-plugin-tsflags");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-plugin-upgrade-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-plugin-verify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-plugin-versionlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-updateonboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yum-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-NetworkManager-dispatcher-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-plugin-aliases-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-plugin-auto-update-debug-info-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-plugin-changelog-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-plugin-copr-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-plugin-fastestmirror-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-plugin-filter-data-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-plugin-fs-snapshot-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-plugin-keys-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-plugin-list-data-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-plugin-local-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-plugin-merge-conf-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-plugin-ovl-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-plugin-post-transaction-actions-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-plugin-pre-transaction-actions-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-plugin-priorities-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-plugin-protectbase-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-plugin-ps-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-plugin-remove-with-leaves-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-plugin-rpm-warm-cache-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-plugin-show-leaves-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-plugin-tmprepo-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-plugin-tsflags-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-plugin-upgrade-helper-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-plugin-verify-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-plugin-versionlock-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-updateonboot-1.1.31-46.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"yum-utils-1.1.31-46.el7_5")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "yum-NetworkManager-dispatcher / yum-plugin-aliases / etc");
}
