#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2577. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128446);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/06");

  script_cve_id("CVE-2019-10222");
  script_xref(name:"RHSA", value:"2019:2577");

  script_name(english:"RHEL 7 : ceph (RHSA-2019:2577)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update is now available for Red Hat Ceph Storage 3.3 on Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat Ceph Storage is a scalable, open, software-defined storage
platform that combines the most stable version of the Ceph storage
system with a Ceph management platform, deployment utilities, and
support services.

Security Fix(es) :

* ceph: Unauthenticated clients can crash ceph RGW configured with
beast as frontend (CVE-2019-10222)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:2577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-10222"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mgr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcephfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcephfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librados-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libradosstriper1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librgw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rbd-mirror");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:2577";
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

  if (! (rpm_exists(release:"RHEL7", rpm:"librados2-12.*\.el7cp"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Ceph Storage");

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-base-12.2.12-48.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-common-12.2.12-48.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-debuginfo-12.2.12-48.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-fuse-12.2.12-48.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-mds-12.2.12-48.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-mgr-12.2.12-48.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-mon-12.2.12-48.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-radosgw-12.2.12-48.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-selinux-12.2.12-48.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-test-12.2.12-48.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libcephfs-devel-12.2.12-48.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libcephfs2-12.2.12-48.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librados-devel-12.2.12-48.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librados2-12.2.12-48.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libradosstriper1-12.2.12-48.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librbd-devel-12.2.12-48.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librbd1-12.2.12-48.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librgw-devel-12.2.12-48.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librgw2-12.2.12-48.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-cephfs-12.2.12-48.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-rados-12.2.12-48.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-rbd-12.2.12-48.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-rgw-12.2.12-48.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rbd-mirror-12.2.12-48.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ceph-base / ceph-common / ceph-debuginfo / ceph-fuse / ceph-mds / etc");
  }
}
