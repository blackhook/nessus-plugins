#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0857 and 
# CentOS Errata and Security Advisory 2011:0857 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(55110);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-0862", "CVE-2011-0864", "CVE-2011-0865", "CVE-2011-0867", "CVE-2011-0868", "CVE-2011-0869", "CVE-2011-0871");
  script_xref(name:"RHSA", value:"2011:0857");

  script_name(english:"CentOS 5 : java-1.6.0-openjdk (CESA-2011:0857)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.6.0-openjdk packages that fix several security issues
are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

These packages provide the OpenJDK 6 Java Runtime Environment and the
OpenJDK 6 Software Development Kit.

Integer overflow flaws were found in the way Java2D parsed JPEG images
and user-supplied fonts. An attacker could use these flaws to execute
arbitrary code with the privileges of the user running an untrusted
applet or application. (CVE-2011-0862)

It was found that the MediaTracker implementation created Component
instances with unnecessary access privileges. A remote attacker could
use this flaw to elevate their privileges by utilizing an untrusted
applet or application that uses Swing. (CVE-2011-0871)

A flaw was found in the HotSpot component in OpenJDK. Certain bytecode
instructions confused the memory management within the Java Virtual
Machine (JVM), resulting in an applet or application crashing.
(CVE-2011-0864)

An information leak flaw was found in the NetworkInterface class. An
untrusted applet or application could use this flaw to access
information about available network interfaces that should only be
available to privileged code. (CVE-2011-0867)

An incorrect float-to-long conversion, leading to an overflow, was
found in the way certain objects (such as images and text) were
transformed in Java2D. A remote attacker could use this flaw to crash
an untrusted applet or application that uses Java2D. (CVE-2011-0868)

It was found that untrusted applets and applications could misuse a
SOAP connection to incorrectly set global HTTP proxy settings instead
of setting them in a local scope. This flaw could be used to intercept
HTTP requests. (CVE-2011-0869)

A flaw was found in the way signed objects were deserialized. If
trusted and untrusted code were running in the same Java Virtual
Machine (JVM), and both were deserializing the same signed object, the
untrusted code could modify said object by using this flaw to bypass
the validation checks on signed objects. (CVE-2011-0865)

Note: All of the above flaws can only be remotely triggered in OpenJDK
by calling the 'appletviewer' application.

All users of java-1.6.0-openjdk are advised to upgrade to these
updated packages, which provide OpenJDK 6 b20 / IcedTea 1.9.8 and
resolve these issues. All running instances of OpenJDK Java must be
restarted for the update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-June/017617.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?460f8948"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-June/017618.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8c5ac104"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-1.6.0.0-1.22.1.9.8.el5_6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.22.1.9.8.el5_6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.22.1.9.8.el5_6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.22.1.9.8.el5_6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.22.1.9.8.el5_6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-openjdk / java-1.6.0-openjdk-demo / etc");
}
