#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0448. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89954);
  script_version("2.13");
  script_cvs_date("Date: 2019/10/24 15:35:41");

  script_cve_id("CVE-2015-7560");
  script_xref(name:"RHSA", value:"2016:0448");

  script_name(english:"RHEL 6 / 7 : samba (RHSA-2016:0448)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba packages that fix one security issue are now available
for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) or Common Internet File System (CIFS) protocol, which allows
PC-compatible machines to share files, printers, and other
information.

A flaw was found in the way Samba handled ACLs on symbolic links. An
authenticated user could use this flaw to gain access to an arbitrary
file or directory by overwriting its ACL. (CVE-2015-7560)

Red Hat would like to thank the Samba project for reporting this
issue. Upstream acknowledges Jeremy Allison (Google) and the Samba
team as the original reporters.

All samba users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. After
installing this update, the smb service will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2016:0448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-7560"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ctdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwbclient-devel");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-test-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-vfs-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:0448";
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
  if (rpm_check(release:"RHEL6", reference:"libsmbclient-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libsmbclient-devel-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-client-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-client-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-client-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", reference:"samba-common-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", reference:"samba-debuginfo-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-doc-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-doc-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-doc-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-domainjoin-gui-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-domainjoin-gui-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-domainjoin-gui-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-glusterfs-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-swat-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-swat-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-swat-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-winbind-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-winbind-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-winbind-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", reference:"samba-winbind-clients-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", reference:"samba-winbind-devel-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-winbind-krb5-locator-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-winbind-krb5-locator-3.6.23-25.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-winbind-krb5-locator-3.6.23-25.el6_7")) flag++;


  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ctdb-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"ctdb-devel-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ctdb-devel-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ctdb-tests-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libsmbclient-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libsmbclient-devel-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libwbclient-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libwbclient-devel-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"samba-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"samba-client-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-client-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"samba-client-libs-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"samba-common-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"samba-common-libs-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-common-libs-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"samba-common-tools-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-common-tools-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"samba-dc-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-dc-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"samba-dc-libs-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-dc-libs-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"samba-debuginfo-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"samba-devel-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"samba-libs-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"samba-pidl-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"samba-python-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-python-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"samba-test-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-test-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"samba-test-devel-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-test-devel-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"samba-test-libs-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-vfs-glusterfs-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"samba-winbind-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-winbind-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"samba-winbind-clients-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-winbind-clients-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"samba-winbind-krb5-locator-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-winbind-krb5-locator-4.2.3-12.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"samba-winbind-modules-4.2.3-12.el7_2")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ctdb / ctdb-devel / ctdb-tests / libsmbclient / libsmbclient-devel / etc");
  }
}
