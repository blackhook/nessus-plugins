#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1972. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112173);
  script_version("1.6");
  script_cvs_date("Date: 2019/10/24 15:35:41");

  script_cve_id("CVE-2016-7031");
  script_xref(name:"RHSA", value:"2016:1972");

  script_name(english:"RHEL 7 : Red Hat Ceph Storage 1.3.3 (RHSA-2016:1972)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Red Hat Ceph Storage 1.3.3 that fixes one security issue, multiple
bugs, and adds various enhancements is now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat Ceph Storage is a scalable, open, software-defined storage
platform that combines the most stable version of the Ceph storage
system with a Ceph management platform, deployment utilities, and
support services.

Security Fix(es) :

* A flaw was found in Ceph RGW code which allows an anonymous user to
list contents of RGW bucket by bypassing ACL which should only allow
authenticated users to list contents of bucket. (CVE-2016-7031)

For detailed information on changes in this release, see the Red Hat
Ceph Storage 1.3.3 Release Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2016:1972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-7031"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-deploy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librados2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librbd1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:radosgw-agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/29");
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
  rhsa = "RHSA-2016:1972";
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

  if (! (rpm_exists(release:"RHEL7", rpm:"ceph-mon-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Ceph Storage");

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-common-0.94.9-3.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-debuginfo-0.94.9-3.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ceph-deploy-1.5.36-1.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-radosgw-0.94.9-3.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-selinux-0.94.9-3.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librados2-0.94.9-3.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librados2-devel-0.94.9-3.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librbd1-0.94.9-3.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librbd1-devel-0.94.9-3.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-rados-0.94.9-3.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-rbd-0.94.9-3.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", reference:"radosgw-agent-1.2.7-1.el7cp")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ceph-common / ceph-debuginfo / ceph-deploy / ceph-radosgw / etc");
  }
}
