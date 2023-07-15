#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1512 and 
# CentOS Errata and Security Advisory 2012:1512 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63100);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-5134");
  script_bugtraq_id(56684);
  script_xref(name:"RHSA", value:"2012:1512");

  script_name(english:"CentOS 5 / 6 : libxml2 (CESA-2012:1512)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libxml2 packages that fix one security issue are now available
for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The libxml2 library is a development toolbox providing the
implementation of various XML standards.

A heap-based buffer underflow flaw was found in the way libxml2
decoded certain entities. A remote attacker could provide a specially
crafted XML file that, when opened in an application linked against
libxml2, would cause the application to crash or, potentially, execute
arbitrary code with the privileges of the user running the
application. (CVE-2012-5134)

All users of libxml2 are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. The desktop
must be restarted (log out, then log back in) for this update to take
effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-November/019018.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2fee1f03"
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-November/019019.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85157602"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5134");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x / 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"libxml2-2.6.26-2.1.15.el5_8.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libxml2-devel-2.6.26-2.1.15.el5_8.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libxml2-python-2.6.26-2.1.15.el5_8.6")) flag++;

if (rpm_check(release:"CentOS-6", reference:"libxml2-2.7.6-8.el6_3.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libxml2-devel-2.7.6-8.el6_3.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libxml2-python-2.7.6-8.el6_3.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libxml2-static-2.7.6-8.el6_3.4")) flag++;


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
