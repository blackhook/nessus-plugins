#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0214 and 
# CentOS Errata and Security Advisory 2011:0214 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(53419);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-4476");
  script_bugtraq_id(46091);
  script_xref(name:"RHSA", value:"2011:0214");

  script_name(english:"CentOS 5 : java-1.6.0-openjdk (CESA-2011:0214)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.6.0-openjdk packages that fix one security issue are
now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

These packages provide the OpenJDK 6 Java Runtime Environment and the
OpenJDK 6 Software Development Kit.

A denial of service flaw was found in the way certain strings were
converted to Double objects. A remote attacker could use this flaw to
cause Java-based applications to hang, for instance if they parse
Double values in a specially crafted HTTP request. (CVE-2010-4476)

All users of java-1.6.0-openjdk are advised to upgrade to these
updated packages, which resolve this issue. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-April/017311.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5355c5a8"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-April/017312.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f84d847f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/15");
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
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-1.6.0.0-1.18.b17.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.18.b17.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.18.b17.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.18.b17.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.18.b17.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-openjdk / java-1.6.0-openjdk-demo / etc");
}
