#%NASL_MIN_LEVEL 999999

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:1136. The text 
# itself is copyright (C) Red Hat, Inc.
#
# @DEPRECATED@
#
# Disabled on 2018/06/15. The packages referenced as fixes do not exist.
#

include("compat.inc");

if (description)
{
  script_id(109159);
  script_version("1.4");
  script_cvs_date("Date: 2018/07/20  0:18:52");

  script_cve_id("CVE-2018-1088");
  script_xref(name:"RHSA", value:"2018:1136");

  script_name(english:"RHEL 7 : glusterfs (RHSA-2018:1136) (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for glusterfs is now available for Native Client for Red Hat
Enterprise Linux 7 for Red Hat Storage and Red Hat Gluster Storage 3.3
for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

GlusterFS is a key building block of Red Hat Gluster Storage. It is
based on a stackable user-space design and can deliver exceptional
performance for diverse workloads. GlusterFS aggregates various
storage servers over network interconnections into one large, parallel
network file system.

Security Fix(es) :

* glusterfs: Privilege escalation via gluster_shared_storage when
snapshot scheduling is enabled (CVE-2018-1088)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

This issue was discovered by John Strunk (Red Hat).

Disabled on 2018/06/15. The packages referenced as fixes do not exist."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/articles/3414511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2018-1136.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2018-1088.html"
  );
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-api-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-client-xlators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-rdma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gluster");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}
exit(0, "This plugin has been deprecated. The packages referenced as fixes do not exist.");

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:1136";
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
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-3.8.4-54.6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-api-3.8.4-54.6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-api-devel-3.8.4-54.6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-cli-3.8.4-54.6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-client-xlators-3.8.4-54.6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-debuginfo-3.8.4-54.6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-devel-3.8.4-54.6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-fuse-3.8.4-54.6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-libs-3.8.4-54.6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-rdma-3.8.4-54.6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-gluster-3.8.4-54.6.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glusterfs / glusterfs-api / glusterfs-api-devel / glusterfs-cli / etc");
  }
}
