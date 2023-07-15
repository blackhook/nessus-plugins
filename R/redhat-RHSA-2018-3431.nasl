#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:3431. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(118582);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/06");

  script_cve_id(
    "CVE-2018-14651",
    "CVE-2018-14652",
    "CVE-2018-14653",
    "CVE-2018-14654",
    "CVE-2018-14659",
    "CVE-2018-14660",
    "CVE-2018-14661"
  );
  script_xref(name:"RHSA", value:"2018:3431");

  script_name(english:"RHEL 6 : glusterfs (RHSA-2018:3431)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Updated glusterfs packages that fix multiple security issues and bugs
are now available for Red Hat Gluster Storage 3.4 on Red Hat
Enterprise Linux 6.

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

* glusterfs: glusterfs server exploitable via symlinks to relative
paths (CVE-2018-14651)

* glusterfs: Buffer overflow in 'features/locks' translator allows for
denial of service (CVE-2018-14652)

* glusterfs: Heap-based buffer overflow via 'gf_getspec_req' RPC
message (CVE-2018-14653)

* glusterfs: 'features/index' translator can create arbitrary, empty
files (CVE-2018-14654)

* glusterfs: Unlimited file creation via 'GF_XATTR_IOSTATS_DUMP_KEY'
xattr allows for denial of service (CVE-2018-14659)

* glusterfs: Repeat use of 'GF_META_LOCK_KEY' xattr allows for memory
exhaustion (CVE-2018-14660)

* glusterfs: features/locks translator passes an user-controlled
string to snprintf without a proper format string resulting in a
denial of service (CVE-2018-14661)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank Michael Hanselmann (hansmi.ch) for
reporting these issues.

This update provides the following bug fix(es) :

* MD5 instances are replaced with FIPS compliant SHA256 checksums and
glusterd no longer crashes when run on a FIPS enabled machine.
(BZ#1459709)

* The flock is unlocked specifically and the status file is updated so
that the reference is not leaked to any worker or agent process. As a
result of this fix, all workers come up without fail. (BZ#1623749)

* All HTIME index files are checked for the specified start and end
times, and the History API does not fail when multiple HTIME files
exist. (BZ#1627639)

* After upgrading to Red Hat Gluster Storage 3.4 from earlier versions
of Red Hat Gluster Storage, the volume size displayed by the df
command was smaller than the actual volume size. This has been fixed
and the df command now shows the correct size for all volumes.
(BZ#1630997)

* The algorithm to disable the eager-lock is modified and it disables
only when multiple write operations are trying to modify a file at the
same time. This led to performance improvement while a write operation
is performed on a file irrespective of the number of times it is
opened at the same time for a read operation. (BZ#1630688)

* heal-info does not consider the presence of dirty markers as an
indication of split-brain and does not display these entries to be in
a split-brain state. (BZ#1610743)

All users of Red Hat Gluster Storage are advised to upgrade to these
updated packages, which provide numerous bug fixes and enhancements.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:3431");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-14651");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-14652");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-14653");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-14654");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-14659");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-14660");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-14661");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14654");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-14653");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-api-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-client-xlators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-events");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-ganesha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-geo-replication");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-rdma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-storage-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:3431";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"glusterfs-server-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "GlusterFS Server");

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-3.12.2-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-api-3.12.2-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-api-devel-3.12.2-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-cli-3.12.2-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-client-xlators-3.12.2-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-debuginfo-3.12.2-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-devel-3.12.2-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-events-3.12.2-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-fuse-3.12.2-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-ganesha-3.12.2-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-geo-replication-3.12.2-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-libs-3.12.2-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-rdma-3.12.2-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-server-3.12.2-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python2-gluster-3.12.2-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"redhat-storage-server-3.4.1.0-1.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glusterfs / glusterfs-api / glusterfs-api-devel / glusterfs-cli / etc");
  }
}
