#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0513 and 
# CentOS Errata and Security Advisory 2014:0513 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74094);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-2877", "CVE-2014-0191");
  script_bugtraq_id(61050, 67233);
  script_xref(name:"RHSA", value:"2014:0513");

  script_name(english:"CentOS 6 : libxml2 (CESA-2014:0513)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libxml2 packages that fix two security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The libxml2 library is a development toolbox providing the
implementation of various XML standards.

It was discovered that libxml2 loaded external parameter entities even
when entity substitution was disabled. A remote attacker able to
provide a specially crafted XML file to an application linked against
libxml2 could use this flaw to conduct XML External Entity (XXE)
attacks, possibly resulting in a denial of service or an information
leak on the system. (CVE-2014-0191)

An out-of-bounds read flaw was found in the way libxml2 detected the
end of an XML file. A remote attacker could provide a specially
crafted XML file that, when processed by an application linked against
libxml2, could cause the application to crash. (CVE-2013-2877)

The CVE-2014-0191 issue was discovered by Daniel P. Berrange of Red
Hat.

All libxml2 users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The desktop
must be restarted (log out, then log back in) for this update to take
effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-May/020303.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dfdcee6a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2877");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"libxml2-2.7.6-14.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libxml2-devel-2.7.6-14.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libxml2-python-2.7.6-14.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libxml2-static-2.7.6-14.el6_5.1")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2 / libxml2-devel / libxml2-python / libxml2-static");
}
