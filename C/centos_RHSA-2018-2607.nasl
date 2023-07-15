#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2607 and 
# CentOS Errata and Security Advisory 2018:2607 respectively.
#

include("compat.inc");

if (description)
{
  script_id(118982);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2018-10904", "CVE-2018-10907", "CVE-2018-10911", "CVE-2018-10913", "CVE-2018-10914", "CVE-2018-10923", "CVE-2018-10926", "CVE-2018-10927", "CVE-2018-10928", "CVE-2018-10929", "CVE-2018-10930");
  script_xref(name:"RHSA", value:"2018:2607");

  script_name(english:"CentOS 7 : glusterfs (CESA-2018:2607)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Updated glusterfs packages that fix multiple security issues and bugs,
and add various enhancements are now available for Red Hat Gluster
Storage 3.4 on Red Hat Enterprise Linux 7.

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

Additional Changes :

These updated glusterfs packages include numerous bug fixes and
enhancements. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Gluster Storage 3.4
Release Notes for information on the most significant of these 
changes :

https://access.redhat.com/site/documentation/en-US/red_hat_gluster_sto
rage/3.4/ html/3.4_release_notes/

All users of Red Hat Gluster Storage are advised to upgrade to these
updated packages, which provide numerous bug fixes and enhancements."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005411.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12b2bbf4"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected glusterfs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10904");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glusterfs-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glusterfs-api-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glusterfs-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glusterfs-client-xlators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glusterfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glusterfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glusterfs-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glusterfs-rdma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-gluster");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glusterfs-3.12.2-18.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glusterfs-api-3.12.2-18.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glusterfs-api-devel-3.12.2-18.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glusterfs-cli-3.12.2-18.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glusterfs-client-xlators-3.12.2-18.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glusterfs-devel-3.12.2-18.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glusterfs-fuse-3.12.2-18.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glusterfs-libs-3.12.2-18.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glusterfs-rdma-3.12.2-18.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python2-gluster-3.12.2-18.el7")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glusterfs / glusterfs-api / glusterfs-api-devel / glusterfs-cli / etc");
}
