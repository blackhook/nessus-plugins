#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0818. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63843);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-3503", "CVE-2007-3655", "CVE-2007-3698", "CVE-2007-3922");
  script_xref(name:"RHSA", value:"2007:0818");

  script_name(english:"RHEL 4 : java-1.5.0-sun (RHSA-2007:0818)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.5.0-sun packages that correct several security issues
are available for Red Hat Enterprise Linux 4 Extras.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

The Java Runtime Environment (JRE) contains the software and tools
that users need to run applets and applications written using the Java
programming language.

The Javadoc tool was able to generate HTML documentation pages that
contained cross-site scripting (XSS) vulnerabilities. A remote
attacker could use this to inject arbitrary web script or HTML.
(CVE-2007-3503)

The Java Web Start URL parsing component contained a buffer overflow
vulnerability within the parsing code for JNLP files. A remote
attacker could create a malicious JNLP file that could trigger this
flaw and execute arbitrary code when opened. (CVE-2007-3655)

The JSSE component did not correctly process SSL/TLS handshake
requests. A remote attacker who is able to connect to a JSSE-based
service could trigger this flaw leading to a denial-of-service.
(CVE-2007-3698)

A flaw was found in the applet class loader. An untrusted applet could
use this flaw to circumvent network access restrictions, possibly
connecting to services hosted on the machine that executed the applet.
(CVE-2007-3922)

All users of java-sun-1.5.0 should upgrade to these packages, which
contain Sun Java 1.5.0 Update 12 that corrects these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3503.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3655.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3698.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3922.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-0818.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.5.0-sun-1.5.0.12-1jpp.2.el4")) flag++;
if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-sun-1.5.0.12-1jpp.2.el4")) flag++;
if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.5.0-sun-demo-1.5.0.12-1jpp.2.el4")) flag++;
if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-sun-demo-1.5.0.12-1jpp.2.el4")) flag++;
if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.5.0-sun-devel-1.5.0.12-1jpp.2.el4")) flag++;
if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-sun-devel-1.5.0.12-1jpp.2.el4")) flag++;
if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.5.0-sun-jdbc-1.5.0.12-1jpp.2.el4")) flag++;
if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-sun-jdbc-1.5.0.12-1jpp.2.el4")) flag++;
if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.5.0-sun-plugin-1.5.0.12-1jpp.2.el4")) flag++;
if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.5.0-sun-src-1.5.0.12-1jpp.2.el4")) flag++;
if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-sun-src-1.5.0.12-1jpp.2.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
