#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:562. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(18687);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2004-0175", "CVE-2005-0488", "CVE-2005-1175", "CVE-2005-1689");
  script_xref(name:"RHSA", value:"2005:562");

  script_name(english:"RHEL 2.1 / 3 : krb5 (RHSA-2005:562)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5 packages which fix multiple security issues are now
available for Red Hat Enterprise Linux 2.1 and 3.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

[Updated 26 Sep 2005] krb5-server packages have been added to this
advisory for Red Hat Enterprise Linux 3 WS and Red Hat Enterprise
Linux 3 Desktop.

Kerberos is a networked authentication system which uses a trusted
third party (a KDC) to authenticate clients and servers to each other.

A double-free flaw was found in the krb5_recvauth() routine which may
be triggered by a remote unauthenticated attacker. Although no exploit
is currently known to exist, this issue could potentially be exploited
to allow arbitrary code execution on a Key Distribution Center (KDC).
The Common Vulnerabilities and Exposures project assigned the name
CVE-2005-1689 to this issue.

Daniel Wachdorf discovered a single byte heap overflow in the
krb5_unparse_name() function, part of krb5-libs. Sucessful
exploitation of this flaw would lead to a denial of service (crash).
To trigger this flaw an attacker would need to have control of a
kerberos realm that shares a cross-realm key with the target, making
exploitation of this flaw unlikely. (CVE-2005-1175).

Gael Delalleau discovered an information disclosure issue in the way
some telnet clients handle messages from a server. An attacker could
construct a malicious telnet server that collects information from the
environment of any victim who connects to it using the Kerberos-aware
telnet client (CVE-2005-0488).

The rcp protocol allows a server to instruct a client to write to
arbitrary files outside of the current directory. This could
potentially cause a security issue if a user uses the Kerberos-aware
rcp to copy files from a malicious server (CVE-2004-0175).

All users of krb5 should update to these erratum packages which
contain backported patches to correct these issues. Red Hat would like
to thank the MIT Kerberos Development Team for their responsible
disclosure of these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-0175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-1175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-1689"
  );
  # http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2005-003-recvauth.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?20d6a900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2005-002-kdc.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2005:562"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(22, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(2\.1|3)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2005:562";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"krb5-devel-1.2.2-37")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"krb5-libs-1.2.2-37")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"krb5-server-1.2.2-37")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"krb5-workstation-1.2.2-37")) flag++;

  if (rpm_check(release:"RHEL3", reference:"krb5-devel-1.2.7-47")) flag++;
  if (rpm_check(release:"RHEL3", reference:"krb5-libs-1.2.7-47")) flag++;
  if (rpm_check(release:"RHEL3", reference:"krb5-server-1.2.7-47")) flag++;
  if (rpm_check(release:"RHEL3", reference:"krb5-workstation-1.2.7-47")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-devel / krb5-libs / krb5-server / krb5-workstation");
  }
}
