#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2261. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111364);
  script_version("1.9");
  script_cvs_date("Date: 2019/10/24 15:35:45");

  script_cve_id("CVE-2018-10861", "CVE-2018-1128", "CVE-2018-1129");
  script_xref(name:"RHSA", value:"2018:2261");

  script_name(english:"RHEL 7 : Red Hat Ceph Storage 2.5 (RHSA-2018:2261)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for ceph is now available for Red Hat Ceph Storage 2.5 for
Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat Ceph Storage is a scalable, open, software-defined storage
platform that combines the most stable version of the Ceph storage
system with a Ceph management platform, deployment utilities, and
support services.

Security Fix(es) :

* ceph: cephx protocol is vulnerable to replay attack (CVE-2018-1128)

* ceph: cephx uses weak signatures (CVE-2018-1129)

* ceph: ceph-mon does not perform authorization on OSD pool ops
(CVE-2018-10861)

For more details about the security issue(s), including the impact, a
CVSS score and other related information refer to the CVE page(s)
listed in the Reference section.

Enhancement(s) :

* Ceph OSDs now logs when they shutdown due to disk operations timing
out by default. (BZ#1568897)

* The `radosgw-admin orphans find` command can inadvertently remove
data objects still in use, if followed by another operation, such as,
a `rados rm` command. Users are now warned before attempting to
produce lists of potentially orphaned objects. (BZ#1573656)

* The 'ceph-osdomap-tool' now has a 'compact' command to perform
offline compaction on an OSD's 'omap' directory. (BZ#1574231)

* For S3 and Swift protocols, an option to list buckets/containers in
natural (partial) order has been added. Listing containers in sorted
order is canonical in both protocols, but is costly, and not required
by some client applications. The performance and workload cost of S3
and Swift bucket/ container listings is reduced for sharded
buckets/containers when the `allow_unordered` extension is used.
(BZ#1595374)

* An asynchronous mechanism for executing the Ceph Object Gateway
garbage collection using the `librados` APIs has been introduced. The
original garbage collection mechanism serialized all processing, and
lagged behind applications in specific workloads. Garbage collection
performance has been significantly improved, and can be tuned to
specific site requirements. (BZ #1595383)

Bug Fix(es) :

These updated ceph packages include numerous bug fixes. Space
precludes documenting all of these changes in this advisory. Users are
directed to the Red Hat Ceph Storage 2.5 Release Notes for information
on the most significant bug fixes for this release :

https://access.redhat.com/documentation/en-us/red_hat_ceph_storage/2.5
/html/ release_notes/bug_fixes"
  );
  # https://access.redhat.com/documentation/en-us/red_hat_ceph_storage/2.5/html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1dc6198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:2261"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1128"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-10861"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcephfs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcephfs1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librados2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librbd1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librgw2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rbd-mirror");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/27");
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
  rhsa = "RHSA-2018:2261";
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

  if (! (rpm_exists(release:"RHEL7", rpm:"ceph-base-10.2.10-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Ceph Storage");

  if (rpm_check(release:"RHEL7", reference:"ceph-ansible-3.0.39-1.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-base-10.2.10-28.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-common-10.2.10-28.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-debuginfo-10.2.10-28.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-fuse-10.2.10-28.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-mds-10.2.10-28.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-radosgw-10.2.10-28.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-selinux-10.2.10-28.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libcephfs1-10.2.10-28.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libcephfs1-devel-10.2.10-28.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librados2-10.2.10-28.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librados2-devel-10.2.10-28.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librbd1-10.2.10-28.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librbd1-devel-10.2.10-28.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librgw2-10.2.10-28.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librgw2-devel-10.2.10-28.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-cephfs-10.2.10-28.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-rados-10.2.10-28.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-rbd-10.2.10-28.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rbd-mirror-10.2.10-28.el7cp")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ceph-ansible / ceph-base / ceph-common / ceph-debuginfo / ceph-fuse / etc");
  }
}
