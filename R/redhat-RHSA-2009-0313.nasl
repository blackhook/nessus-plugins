#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0313. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(35772);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-4680", "CVE-2008-4681", "CVE-2008-4682", "CVE-2008-4683", "CVE-2008-4684", "CVE-2008-4685", "CVE-2008-5285", "CVE-2008-6472", "CVE-2009-0599", "CVE-2009-0600");
  script_bugtraq_id(31838, 32422);
  script_xref(name:"RHSA", value:"2009:0313");

  script_name(english:"RHEL 3 / 4 / 5 : wireshark (RHSA-2009:0313)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated wireshark packages that fix several security issues are now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Wireshark is a program for monitoring network traffic. Wireshark was
previously known as Ethereal.

Multiple buffer overflow flaws were found in Wireshark. If Wireshark
read a malformed packet off a network or opened a malformed dump file,
it could crash or, possibly, execute arbitrary code as the user
running Wireshark. (CVE-2008-4683, CVE-2009-0599)

Several denial of service flaws were found in Wireshark. Wireshark
could crash or stop responding if it read a malformed packet off a
network, or opened a malformed dump file. (CVE-2008-4680,
CVE-2008-4681, CVE-2008-4682, CVE-2008-4684, CVE-2008-4685,
CVE-2008-5285, CVE-2009-0600)

Users of wireshark should upgrade to these updated packages, which
contain Wireshark version 1.0.6, and resolve these issues. All running
instances of Wireshark must be restarted for the update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-4680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-4681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-4682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-4683"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-4684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-4685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-5285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-6472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-0599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-0600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2009:0313"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark and / or wireshark-gnome packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2009:0313";
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
  if (rpm_check(release:"RHEL3", reference:"wireshark-1.0.6-EL3.3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"wireshark-gnome-1.0.6-EL3.3")) flag++;


  if (rpm_check(release:"RHEL4", reference:"wireshark-1.0.6-2.el4_7")) flag++;

  if (rpm_check(release:"RHEL4", reference:"wireshark-gnome-1.0.6-2.el4_7")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"wireshark-1.0.6-2.el5_3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"wireshark-1.0.6-2.el5_3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"wireshark-1.0.6-2.el5_3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"wireshark-gnome-1.0.6-2.el5_3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"wireshark-gnome-1.0.6-2.el5_3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"wireshark-gnome-1.0.6-2.el5_3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-gnome");
  }
}
