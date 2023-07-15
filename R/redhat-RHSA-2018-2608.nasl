#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2608. The text 
# itself is copyright (C) Red Hat, Inc.
#
# @DEPRECATED@
#
# Disabled on 2018/11/06. Detection of Gluster Storage Server on
# RHEL 6 is no longer possible due to changes in Gluster package versioning. 

include("compat.inc");

if (description)
{
  script_id(117318);
  script_version("1.5");
  script_cvs_date("Date: 2019/10/24 15:35:45");

  script_cve_id("CVE-2018-10904", "CVE-2018-10907", "CVE-2018-10911", "CVE-2018-10913", "CVE-2018-10914", "CVE-2018-10923", "CVE-2018-10926", "CVE-2018-10927", "CVE-2018-10928", "CVE-2018-10929", "CVE-2018-10930");
  script_xref(name:"RHSA", value:"2018:2608");

  script_name(english:"RHEL 6 : Gluster Storage (RHSA-2018:2608) (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glusterfs packages that fix multiple security issues, several
bugs, and adds various enhancements are now available for Red Hat
Gluster Storage 3.4 on Red Hat Enterprise Linux 6.

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

* glusterfs: Unsanitized file names in debug/io-stats translator can
allow remote attackers to execute arbitrary code (CVE-2018-10904)

* glusterfs: Stack-based buffer overflow in server-rpc-fops.c allows
remote attackers to execute arbitrary code (CVE-2018-10907)

* glusterfs: I/O to arbitrary devices on storage server
(CVE-2018-10923)

* glusterfs: Device files can be created in arbitrary locations
(CVE-2018-10926)

* glusterfs: File status information leak and denial of service
(CVE-2018-10927)

* glusterfs: Improper resolution of symlinks allows for privilege
escalation (CVE-2018-10928)

* glusterfs: Arbitrary file creation on storage server allows for
execution of arbitrary code (CVE-2018-10929)

* glusterfs: Files can be renamed outside volume (CVE-2018-10930)

* glusterfs: Improper deserialization in dict.c:dict_unserialize() can
allow attackers to read arbitrary memory (CVE-2018-10911)

* glusterfs: remote denial of service of gluster volumes via
posix_get_file_contents function in posix-helpers.c (CVE-2018-10914)

* glusterfs: Information Exposure in posix_get_file_contents function
in posix-helpers.c (CVE-2018-10913)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank Michael Hanselmann (hansmi.ch) for
reporting these issues.

Additional changes :

These updated Red Hat Gluster Storage packages include numerous bug
fixes and enhancements. Space precludes documenting all of these
changes in this advisory. Users are directed to the Red Hat Gluster
Storage 3.4 Release Notes for information on the most significant of
these changes :

https://access.redhat.com/documentation/en-us/red_hat_gluster_storage/
3.4/html/ 3.4_release_notes/

All users of Red Hat Gluster Storage are advised to upgrade to these
updated packages, which provide numerous bug fixes and enhancements.

Disabled on 2018/11/06. Detection of Gluster Storage Server on RHEL 6
is no longer possible due to changes in Gluster package versioning."
  );
  # https://access.redhat.com/documentation/en-us/red_hat_gluster_storage/3.4/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?69f9b995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2018-2608.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2018-10904.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2018-10907.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2018-10911.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2018-10913.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2018-10914.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2018-10923.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2018-10926.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2018-10927.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2018-10928.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2018-10929.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2018-10930.html"
  );
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-release-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-storage-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "This plugin has been deprecated. Detection of Gluster Storage Server on RHEL 6 is no longer possible due to changes in Gluster package versioning.");

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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:2608";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"glusterfs-3.12.2"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Gluster Storage");

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-3.12.2-18.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-api-3.12.2-18.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-api-devel-3.12.2-18.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-cli-3.12.2-18.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-client-xlators-3.12.2-18.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-debuginfo-3.12.2-18.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-devel-3.12.2-18.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-events-3.12.2-18.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-fuse-3.12.2-18.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-ganesha-3.12.2-18.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-geo-replication-3.12.2-18.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-libs-3.12.2-18.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-rdma-3.12.2-18.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-server-3.12.2-18.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python2-gluster-3.12.2-18.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"redhat-release-server-6Server-6.10.0.24.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"redhat-storage-server-3.4.0.0-1.el6")) flag++;

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
