#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2612. The text 
# itself is copyright (C) Red Hat, Inc.
#
# @DEPRECATED@
#
# Disabled on 2018/11/06. Detection of Gluster Storage Server on
# RHEL 6 is no longer possible due to changes in Gluster package versioning. 

include("compat.inc");

if (description)
{
  script_id(117319);
  script_version("1.6");
  script_cvs_date("Date: 2019/10/24 15:35:45");

  script_cve_id("CVE-2018-1050", "CVE-2018-10858", "CVE-2018-1139");
  script_xref(name:"RHSA", value:"2018:2612");

  script_name(english:"RHEL 6 : Storage Server (RHSA-2018:2612) (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba packages that fix several security issues and provide
several bug fixes and an enhancement are now available for Red Hat
Gluster Storage 3.4 for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) protocol and the related Common Internet File System (CIFS)
protocol, which allow PC-compatible machines to share files, printers,
and various information.

Security Fix(es) :

* samba: Weak authentication protocol regression (CVE-2018-1139)

* samba: Insufficient input validation in libsmbclient
(CVE-2018-10858)

* samba: NULL pointer indirection in printer server process
(CVE-2018-1050)

Red Hat would like to thank the Samba project for reporting
CVE-2018-1139 and CVE-2018-1050. Upstream acknowledges Vivek Das (Red
Hat) as the original reporter of CVE-2018-1139.

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Bug Fix(es) :

* Previously, sharing a subdirectory of a Gluster volume failed with
an I/O error when the shadow_copy2 vfs object was specified. This
occurred because Gluster volumes are remote file systems, and
shadow_copy2 only detected share paths in the local file system. This
update forces the value of shadow:mountpath to '/', skipping the code
related to mount point detection, and preventing this problem.
However, this fix requires that the glusterfs vfs object is listed
after the shadow_copy2 vfs object in the smb.conf file. (BZ#1379444)

* As of Red Hat Gluster Storage 3.4, the libldb package is no longer
shipped as an independent package in the Red Hat Gluster Storage Samba
channel. The capabilities of the libldb package are now provided by a
combination of the samba-client and samba-client-libs packages. In
addition, the sub-packages previously provided by libldb are now
provided by the samba-client and samba-client-libs packages. The
samba-client sub-package provides ldb-tools, and the samba-client-libs
sub-package provides pyldb. (BZ# 1592794)

Enhancement(s) :

* Red Hat Gluster Storage volumes exported using SMB can now be
mounted on macOS clients using Finder. Configuration instructions are
provided as part of the Red Hat Gluster Storage 3.4 documentation.
(BZ#1446125) Red Hat strongly recommends upgrading to these updated
packages.

Disabled on 2018/11/06. Detection of Gluster Storage Server on RHEL 6
is no longer possible due to changes in Gluster package versioning."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2018-2612.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2018-1050.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2018-1139.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2018-10858.html"
  );
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtalloc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtalloc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtalloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtdb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtevent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtevent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtevent-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pytalloc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pytalloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-tdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-tevent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-krb5-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-vfs-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tdb-tools");
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
  rhsa = "RHSA-2018:2612";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"glusterfs-3.12.2"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Storage Server");

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ctdb-4.7.5-110.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libsmbclient-4.7.5-110.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libsmbclient-devel-4.7.5-110.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libtalloc-2.1.11-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libtalloc-debuginfo-2.1.11-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libtalloc-devel-2.1.11-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libtdb-1.3.15-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libtdb-debuginfo-1.3.15-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libtdb-devel-1.3.15-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libtevent-0.9.35-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libtevent-debuginfo-0.9.35-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libtevent-devel-0.9.35-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libwbclient-4.7.5-110.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libwbclient-devel-4.7.5-110.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pytalloc-2.1.11-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pytalloc-devel-2.1.11-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-tdb-1.3.15-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-tevent-0.9.35-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-4.7.5-110.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-client-4.7.5-110.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-client-libs-4.7.5-110.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"samba-common-4.7.5-110.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-common-libs-4.7.5-110.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-common-tools-4.7.5-110.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-dc-4.7.5-110.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-dc-libs-4.7.5-110.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-debuginfo-4.7.5-110.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-devel-4.7.5-110.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-krb5-printing-4.7.5-110.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-libs-4.7.5-110.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"samba-pidl-4.7.5-110.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-python-4.7.5-110.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-vfs-glusterfs-4.7.5-110.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-winbind-4.7.5-110.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-winbind-clients-4.7.5-110.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-winbind-krb5-locator-4.7.5-110.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-winbind-modules-4.7.5-110.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"tdb-tools-1.3.15-4.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ctdb / libsmbclient / libsmbclient-devel / libtalloc / etc");
  }
}
