#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1806. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71293);
  script_version("1.29");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-4408", "CVE-2013-4475");
  script_bugtraq_id(63646, 64191);
  script_xref(name:"RHSA", value:"2013:1806");

  script_name(english:"RHEL 5 / 6 : samba and samba3x (RHSA-2013:1806)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba3x and samba packages that fix two security issues are
now available for Red Hat Enterprise Linux 5 and 6 respectively.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) or Common Internet File System (CIFS) protocol, which allows
PC-compatible machines to share files, printers, and other
information.

A heap-based buffer overflow flaw was found in the DCE-RPC client code
in Samba. A specially crafted DCE-RPC packet could cause various Samba
programs to crash or, possibly, execute arbitrary code when parsed. A
malicious or compromised Active Directory Domain Controller could use
this flaw to compromise the winbindd daemon running with root
privileges. (CVE-2013-4408)

A flaw was found in the way Samba performed ACL checks on alternate
file and directory data streams. An attacker able to access a CIFS
share with alternate stream support enabled could access alternate
data streams regardless of the underlying file or directory ACL
permissions. (CVE-2013-4475)

Red Hat would like to thank the Samba project for reporting
CVE-2013-4408. Upstream acknowledges Stefan Metzmacher and Michael
Adam of SerNet as the original reporters of this issue.

All users of Samba are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing this update, the smb service will be restarted
automatically."
  );
  # http://www.samba.org/samba/security/CVE-2013-4408
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/security/CVE-2013-4408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2013:1806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-4408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-4475"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1806";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-3.6.6-0.138.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-3.6.6-0.138.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-3.6.6-0.138.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-client-3.6.6-0.138.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-client-3.6.6-0.138.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-client-3.6.6-0.138.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-common-3.6.6-0.138.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-common-3.6.6-0.138.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-common-3.6.6-0.138.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", reference:"samba3x-debuginfo-3.6.6-0.138.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-doc-3.6.6-0.138.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-doc-3.6.6-0.138.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-doc-3.6.6-0.138.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-domainjoin-gui-3.6.6-0.138.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-domainjoin-gui-3.6.6-0.138.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-domainjoin-gui-3.6.6-0.138.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-swat-3.6.6-0.138.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-swat-3.6.6-0.138.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-swat-3.6.6-0.138.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", reference:"samba3x-winbind-3.6.6-0.138.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", reference:"samba3x-winbind-devel-3.6.6-0.138.el5_10")) flag++;


  if (rpm_check(release:"RHEL6", reference:"libsmbclient-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libsmbclient-devel-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-client-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-client-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-client-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"samba-common-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"samba-debuginfo-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-doc-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-doc-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-doc-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-domainjoin-gui-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-domainjoin-gui-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-domainjoin-gui-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-swat-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-swat-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-swat-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-winbind-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-winbind-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-winbind-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"samba-winbind-clients-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"samba-winbind-devel-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-winbind-krb5-locator-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-winbind-krb5-locator-3.6.9-167.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-winbind-krb5-locator-3.6.9-167.el6_5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsmbclient / libsmbclient-devel / samba / samba-client / etc");
  }
}
