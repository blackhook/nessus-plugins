#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:3242. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(118536);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");

  script_cve_id("CVE-2018-10911");
  script_xref(name:"RHSA", value:"2018:3242");

  script_name(english:"RHEL 7 : glusterfs (RHSA-2018:3242)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for glusterfs is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

GlusterFS is a key building block of Red Hat Gluster Storage. It is
based on a stackable user-space design and can deliver exceptional
performance for diverse workloads. GlusterFS aggregates various
storage servers over network interconnections into one large, parallel
network file system.

The following packages have been upgraded to a later upstream version:
glusterfs (3.12.2). (BZ#1579734)

Security Fix(es) :

* glusterfs: Improper deserialization in dict.c:dict_unserialize() can
allow attackers to read arbitrary memory (CVE-2018-10911)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank Michael Hanselmann (hansmi.ch) for
reporting this issue.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.6 Release Notes linked from the References section.");
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3395ff0b");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:3242");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-10911");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10911");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/31");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-gluster");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:3242";
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
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-3.12.2-18.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-api-3.12.2-18.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-api-devel-3.12.2-18.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-cli-3.12.2-18.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-client-xlators-3.12.2-18.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-debuginfo-3.12.2-18.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-devel-3.12.2-18.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-fuse-3.12.2-18.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-libs-3.12.2-18.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-rdma-3.12.2-18.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python2-gluster-3.12.2-18.el7")) flag++;

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
