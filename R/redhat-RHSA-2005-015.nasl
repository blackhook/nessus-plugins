#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:015. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(16148);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2003-0297");
  script_xref(name:"RHSA", value:"2005:015");

  script_name(english:"RHEL 2.1 : pine (RHSA-2005:015)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated Pine package is now available for Red Hat Enterprise Linux
2.1 to fix a denial of service attack.

Pine is an email user agent.

The c-client IMAP client library, as used in Pine 4.44 contains an
integer overflow and integer signedness flaw. An attacker could create
a malicious IMAP server in such a way that it would cause Pine to
crash. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2003-0297 to this issue.

Users of Pine are advised to upgrade to these erratum packages which
contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2003-0297"
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=105294024124163
  script_set_attribute(
    attribute:"see_also",
    value:"https://marc.info/?l=bugtraq&m=105294024124163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2005:015"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pine package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pine");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/13");
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
if (! preg(pattern:"^2\.1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if (cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i386", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2005:015";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"pine-4.44-20")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pine");
  }
}
