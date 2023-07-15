#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0151. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(64029);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-1104", "CVE-2011-1948");
  script_bugtraq_id(37765, 48005);
  script_xref(name:"RHSA", value:"2012:0151");

  script_name(english:"RHEL 5 : conga (RHSA-2012:0151)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated conga packages that fix multiple security issues, several
bugs, and add one enhancement are now available for Red Hat Enterprise
Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The conga packages provide a web-based administration tool for remote
cluster and storage management.

Multiple cross-site scripting (XSS) flaws were found in luci, the
conga web-based administration application. If a remote attacker could
trick a user, who was logged into the luci interface, into visiting a
specially crafted URL, it would lead to arbitrary web script execution
in the context of the user's luci session. (CVE-2010-1104,
CVE-2011-1948)

These updated conga packages include several bug fixes and an
enhancement. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 5.8
Technical Notes, linked to in the References, for information on the
most significant of these changes.

Users of conga are advised to upgrade to these updated packages, which
correct these issues and add this enhancement. After installing the
updated packages, luci must be restarted ('service luci restart') for
the update to take effect."
  );
  # https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/5/html/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?056c0c27"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2012:0151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-1948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2010-1104"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected conga-debuginfo, luci and / or ricci packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:conga-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:luci");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ricci");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0151";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"conga-debuginfo-0.12.2-51.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"conga-debuginfo-0.12.2-51.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"luci-0.12.2-51.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"luci-0.12.2-51.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ricci-0.12.2-51.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ricci-0.12.2-51.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "conga-debuginfo / luci / ricci");
  }
}
