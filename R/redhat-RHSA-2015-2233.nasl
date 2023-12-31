#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2233. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86976);
  script_version("2.12");
  script_cvs_date("Date: 2019/10/24 15:35:40");

  script_cve_id("CVE-2014-8240", "CVE-2014-8241");
  script_xref(name:"RHSA", value:"2015:2233");

  script_name(english:"RHEL 7 : tigervnc (RHSA-2015:2233)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tigervnc packages that fix two security issues, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Virtual Network Computing (VNC) is a remote display system which
allows users to view a computing desktop environment not only on the
machine where it is running, but from anywhere on the Internet and
from a wide variety of machine architectures. TigerVNC is a suite of
VNC servers and clients. The tigervnc packages contain a client which
allows users to connect to other desktops running a VNC server.

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way TigerVNC handled screen sizes. A malicious VNC server
could use this flaw to cause a client to crash or, potentially,
execute arbitrary code on the client. (CVE-2014-8240)

A NULL pointer dereference flaw was found in TigerVNC's XRegion. A
malicious VNC server could use this flaw to cause a client to crash.
(CVE-2014-8241)

The tigervnc packages have been upgraded to upstream version 1.3.1,
which provides a number of bug fixes and enhancements over the
previous version. (BZ#1199453)

This update also fixes the following bug :

* The position of the mouse cursor in the VNC session was not
correctly communicated to the VNC viewer, resulting in cursor
misplacement. The method of displaying the remote cursor has been
changed, and cursor movements on the VNC server are now accurately
reflected on the VNC client. (BZ#1100661)

All tigervnc users are advised to upgrade to these updated packages,
which correct these issues and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2015:2233"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-8240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-8241"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tigervnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tigervnc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tigervnc-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tigervnc-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tigervnc-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tigervnc-server-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tigervnc-server-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tigervnc-server-module");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2015:2233";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"tigervnc-1.3.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tigervnc-1.3.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"tigervnc-debuginfo-1.3.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tigervnc-debuginfo-1.3.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"tigervnc-icons-1.3.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"tigervnc-license-1.3.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"tigervnc-server-1.3.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tigervnc-server-1.3.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"tigervnc-server-applet-1.3.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"tigervnc-server-minimal-1.3.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tigervnc-server-minimal-1.3.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tigervnc-server-module-1.3.1-3.el7")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tigervnc / tigervnc-debuginfo / tigervnc-icons / tigervnc-license / etc");
  }
}
