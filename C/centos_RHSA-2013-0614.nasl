#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0614 and 
# CentOS Errata and Security Advisory 2013:0614 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65167);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-0787");
  script_bugtraq_id(58391);
  script_xref(name:"RHSA", value:"2013:0614");

  script_name(english:"CentOS 5 / 6 : xulrunner (CESA-2013:0614)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xulrunner packages that fix one security issue are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

XULRunner provides the XUL Runtime environment for applications using
the Gecko layout engine.

A flaw was found in the way XULRunner handled malformed web content. A
web page containing malicious content could cause an application
linked against XULRunner (such as Mozilla Firefox) to crash or execute
arbitrary code with the privileges of the user running the
application. (CVE-2013-0787)

Red Hat would like to thank the Mozilla project for reporting this
issue. Upstream acknowledges VUPEN Security via the TippingPoint Zero
Day Initiative project as the original reporter.

For technical details regarding this flaw, refer to the Mozilla
security advisories. You can find a link to the Mozilla advisories in
the References section of this erratum.

All XULRunner users should upgrade to these updated packages, which
correct this issue. After installing the update, applications using
XULRunner must be restarted for the changes to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019273.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d1be364"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019636.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?947540f2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xulrunner packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0787");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", reference:"xulrunner-17.0.3-2.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-17.0.3-2.el5_9")) flag++;

if (rpm_check(release:"CentOS-6", reference:"xulrunner-17.0.3-2.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xulrunner-devel-17.0.3-2.el6.centos")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xulrunner / xulrunner-devel");
}
