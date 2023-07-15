#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1652. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71014);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-0221", "CVE-2013-0222", "CVE-2013-0223");
  script_bugtraq_id(57492, 57516, 57517);
  script_xref(name:"RHSA", value:"2013:1652");

  script_name(english:"RHEL 6 : coreutils (RHSA-2013:1652)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated coreutils packages that fix three security issues, several
bugs, and add two enhancements are now available for Red Hat
Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The coreutils package contains the core GNU utilities. It is a
combination of the old GNU fileutils, sh-utils, and textutils
packages.

It was discovered that the sort, uniq, and join utilities did not
properly restrict the use of the alloca() function. An attacker could
use this flaw to crash those utilities by providing long input
strings. (CVE-2013-0221, CVE-2013-0222, CVE-2013-0223)

These updated coreutils packages include numerous bug fixes and two
enhancements. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 6.5
Technical Notes, linked to in the References, for information on the
most significant of these changes.

All coreutils users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add these
enhancements."
  );
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6b506c4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2013:1652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-0221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-0223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-0222"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected coreutils, coreutils-debuginfo and / or
coreutils-libs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:coreutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:coreutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:coreutils-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/21");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1652";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"coreutils-8.4-31.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"coreutils-8.4-31.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"coreutils-8.4-31.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"coreutils-debuginfo-8.4-31.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"coreutils-debuginfo-8.4-31.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"coreutils-debuginfo-8.4-31.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"coreutils-libs-8.4-31.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"coreutils-libs-8.4-31.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"coreutils-libs-8.4-31.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "coreutils / coreutils-debuginfo / coreutils-libs");
  }
}
