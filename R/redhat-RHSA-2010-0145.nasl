#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0145. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(46268);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2005-4268", "CVE-2010-0624");
  script_bugtraq_id(16057);
  script_xref(name:"RHSA", value:"2010:0145");

  script_name(english:"RHEL 3 : cpio (RHSA-2010:0145)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated cpio package that fixes two security issues is now
available for Red Hat Enterprise Linux 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

GNU cpio copies files into or out of a cpio or tar archive.

A heap-based buffer overflow flaw was found in the way cpio expanded
archive files. If a user were tricked into expanding a specially
crafted archive, it could cause the cpio executable to crash or
execute arbitrary code with the privileges of the user running cpio.
(CVE-2010-0624)

Red Hat would like to thank Jakob Lell for responsibly reporting the
CVE-2010-0624 issue.

A stack-based buffer overflow flaw was found in the way cpio expanded
large archive files. If a user expanded a specially crafted archive,
it could cause the cpio executable to crash. This issue only affected
64-bit platforms. (CVE-2005-4268)

Users of cpio are advised to upgrade to this updated package, which
contains backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-4268"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2010-0624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2010:0145"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cpio package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cpio");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0145";
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
  if (rpm_check(release:"RHEL3", reference:"cpio-2.5-6.RHEL3")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cpio");
  }
}
