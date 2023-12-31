#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0383. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73452);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-6150", "CVE-2013-4496", "CVE-2013-6442");
  script_bugtraq_id(64101, 66232, 66336);
  script_xref(name:"RHSA", value:"2014:0383");

  script_name(english:"RHEL 6 : samba4 (RHSA-2014:0383)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba4 packages that fix three security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) or Common Internet File System (CIFS) protocol, which allows
PC-compatible machines to share files, printers, and other
information.

It was found that certain Samba configurations did not enforce the
password lockout mechanism. A remote attacker could use this flaw to
perform password guessing attacks on Samba user accounts. Note: this
flaw only affected Samba when deployed as a Primary Domain Controller.
(CVE-2013-4496)

A flaw was found in Samba's 'smbcacls' command, which is used to set
or get ACLs on SMB file shares. Certain command line options of this
command would incorrectly remove an ACL previously applied on a file
or a directory, leaving the file or directory without the intended
ACL. (CVE-2013-6442)

A flaw was found in the way the pam_winbind module handled
configurations that specified a non-existent group as required. An
authenticated user could possibly use this flaw to gain access to a
service using pam_winbind in its PAM configuration when group
restriction was intended for access to the service. (CVE-2012-6150)

Red Hat would like to thank the Samba project for reporting
CVE-2013-4496 and CVE-2013-6442, and Sam Richardson for reporting
CVE-2012-6150. Upstream acknowledges Andrew Bartlett as the original
reporter of CVE-2013-4496, and Noel Power as the original reporter of
CVE-2013-6442.

All users of Samba are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing this update, the smb service will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/security/CVE-2012-6150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/security/CVE-2013-4496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/security/CVE-2013-6442"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2014:0383"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-4496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-6150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-6442"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2014:0383";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-client-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-client-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-client-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-common-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-common-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-common-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-dc-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-dc-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-dc-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-dc-libs-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-dc-libs-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-dc-libs-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-debuginfo-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-debuginfo-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-debuginfo-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-devel-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-devel-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-devel-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-libs-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-libs-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-libs-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-pidl-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-pidl-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-pidl-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-python-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-python-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-python-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-swat-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-swat-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-swat-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-test-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-test-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-test-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-winbind-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-winbind-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-winbind-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-winbind-clients-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-winbind-clients-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-winbind-clients-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-winbind-krb5-locator-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-winbind-krb5-locator-4.0.0-61.el6_5.rc4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-winbind-krb5-locator-4.0.0-61.el6_5.rc4")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba4 / samba4-client / samba4-common / samba4-dc / samba4-dc-libs / etc");
  }
}
