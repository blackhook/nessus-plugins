#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0533. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(33462);
  script_version("1.44");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-1447");
  script_bugtraq_id(30131);
  script_xref(name:"CERT", value:"800113");
  script_xref(name:"RHSA", value:"2008:0533");
  script_xref(name:"IAVA", value:"2008-A-0045");

  script_name(english:"RHEL 2.1 / 3 / 4 / 5 : bind (RHSA-2008:0533)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bind packages that help mitigate DNS spoofing attacks are now
available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

[Updated 10th July 2008] We have updated the Enterprise Linux 5
packages in this advisory. The default and sample caching-nameserver
configuration files have been updated so that they do not specify a
fixed query-source port. Administrators wishing to take advantage of
randomized UDP source ports should check their configuration file to
ensure they have not specified fixed query-source ports.

ISC BIND (Berkeley Internet Name Domain) is an implementation of the
DNS (Domain Name System) protocols.

The DNS protocol protects against spoofing attacks by requiring an
attacker to predict both the DNS transaction ID and UDP source port of
a request. In recent years, a number of papers have found problems
with DNS implementations which make it easier for an attacker to
perform DNS cache-poisoning attacks.

Previous versions of BIND did not use randomized UDP source ports. If
an attacker was able to predict the random DNS transaction ID, this
could make DNS cache-poisoning attacks easier. In order to provide
more resilience, BIND has been updated to use a range of random UDP
source ports. (CVE-2008-1447)

Note: This errata also updates SELinux policy on Red Hat Enterprise
Linux 4 and 5 to allow BIND to use random UDP source ports.

Users of BIND are advised to upgrade to these updated packages, which
contain a backported patch to add this functionality.

Red Hat would like to thank Dan Kaminsky for reporting this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-1447"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2008:0533"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-libbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:caching-nameserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:selinux-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:selinux-policy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:selinux-policy-mls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:selinux-policy-strict");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:selinux-policy-targeted");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:selinux-policy-targeted-sources");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(2\.1|3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x / 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0533";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"bind-9.2.1-10.el2")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"bind-devel-9.2.1-10.el2")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"bind-utils-9.2.1-10.el2")) flag++;


  if (rpm_check(release:"RHEL3", reference:"bind-9.2.4-22.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"bind-chroot-9.2.4-22.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"bind-devel-9.2.4-22.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"bind-libs-9.2.4-22.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"bind-utils-9.2.4-22.el3")) flag++;


  if (rpm_check(release:"RHEL4", reference:"bind-9.2.4-28.0.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"bind-chroot-9.2.4-28.0.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"bind-devel-9.2.4-28.0.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"bind-libs-9.2.4-28.0.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"bind-utils-9.2.4-28.0.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"selinux-policy-targeted-1.17.30-2.150.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"selinux-policy-targeted-sources-1.17.30-2.150.el4")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bind-9.3.4-6.0.2.P1.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"bind-9.3.4-6.0.2.P1.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bind-9.3.4-6.0.2.P1.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bind-chroot-9.3.4-6.0.2.P1.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"bind-chroot-9.3.4-6.0.2.P1.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bind-chroot-9.3.4-6.0.2.P1.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"bind-devel-9.3.4-6.0.2.P1.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"bind-libbind-devel-9.3.4-6.0.2.P1.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"bind-libs-9.3.4-6.0.2.P1.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bind-sdb-9.3.4-6.0.2.P1.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"bind-sdb-9.3.4-6.0.2.P1.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bind-sdb-9.3.4-6.0.2.P1.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bind-utils-9.3.4-6.0.2.P1.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"bind-utils-9.3.4-6.0.2.P1.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bind-utils-9.3.4-6.0.2.P1.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"caching-nameserver-9.3.4-6.0.2.P1.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"caching-nameserver-9.3.4-6.0.2.P1.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"caching-nameserver-9.3.4-6.0.2.P1.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"selinux-policy-2.4.6-137.1.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"selinux-policy-devel-2.4.6-137.1.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"selinux-policy-mls-2.4.6-137.1.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"selinux-policy-strict-2.4.6-137.1.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"selinux-policy-targeted-2.4.6-137.1.el5_2")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-devel / bind-libbind-devel / bind-libs / etc");
  }
}
