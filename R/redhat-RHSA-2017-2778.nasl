#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2778. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103453);
  script_version("3.9");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2017-2619", "CVE-2017-9461");
  script_xref(name:"RHSA", value:"2017:2778");

  script_name(english:"RHEL 6 : Storage Server (RHSA-2017:2778)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for samba is now available for Red Hat Gluster Storage 3.3
for RHEL 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) protocol and the related Common Internet File System (CIFS)
protocol, which allow PC-compatible machines to share files, printers,
and various information.

Security Fix(es) :

* A race condition was found in samba server. A malicious samba client
could use this flaw to access files and directories in areas of the
server file system not exported under the share definitions.
(CVE-2017-2619)

* A flaw was found in the way Samba handled dangling symlinks. An
authenticated malicious Samba client could use this flaw to cause the
smbd daemon to enter an infinite loop and use an excessive amount of
CPU and memory. (CVE-2017-9461)

Red Hat would like to thank the Samba project for reporting
CVE-2017-2619. Upstream acknowledges Jann Horn (Google) as the
original reporter of CVE-2017-2619.

Bug Fix(es) :

* In the samba configuration, by default the 'posix locking' is
enabled and 'stat cache' is disabled. Enabling 'posix locking' sends
the file lock request to the bricks too, and disabling 'stat cache'
blocks samba to cache certain information at the samba layer. This led
to decrease in performance of SMB access of Red Hat Gluster Storage
volumes

As a fix, the following two options are included in the samba
configuration file: posix locking = No stat cache = Yes

Due to this, a slight improvement in the performance is observed.
(BZ#1436265)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:2778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-2619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-9461"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ldb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libldb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libldb-devel");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pyldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pyldb-devel");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-vfs-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tdb-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:2778";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"glusterfs-server"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Storage Server");

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ctdb-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ctdb-tests-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ldb-tools-1.1.29-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libldb-1.1.29-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libldb-debuginfo-1.1.29-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libldb-devel-1.1.29-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libsmbclient-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libsmbclient-devel-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libtalloc-2.1.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libtalloc-debuginfo-2.1.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libtalloc-devel-2.1.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libtdb-1.3.12-1.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libtdb-debuginfo-1.3.12-1.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libtdb-devel-1.3.12-1.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libtevent-0.9.31-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libtevent-debuginfo-0.9.31-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libtevent-devel-0.9.31-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libwbclient-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libwbclient-devel-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pyldb-1.1.29-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pyldb-devel-1.1.29-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pytalloc-2.1.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pytalloc-devel-2.1.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-tdb-1.3.12-1.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-tevent-0.9.31-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-client-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-client-libs-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"samba-common-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-common-libs-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-common-tools-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-dc-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-dc-libs-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-debuginfo-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-devel-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-krb5-printing-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-libs-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"samba-pidl-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-python-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-test-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-test-libs-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-vfs-glusterfs-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-winbind-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-winbind-clients-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-winbind-krb5-locator-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-winbind-modules-4.6.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"tdb-tools-1.3.12-1.1.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ctdb / ctdb-tests / ldb-tools / libldb / libldb-debuginfo / etc");
  }
}
