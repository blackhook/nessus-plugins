#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0370 and 
# CentOS Errata and Security Advisory 2011:0370 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(52757);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-3445", "CVE-2011-0024", "CVE-2011-0538", "CVE-2011-0713", "CVE-2011-1138", "CVE-2011-1139", "CVE-2011-1140", "CVE-2011-1141", "CVE-2011-1142", "CVE-2011-1143");
  script_bugtraq_id(43197, 46167, 46626, 46796);
  script_xref(name:"RHSA", value:"2011:0370");

  script_name(english:"CentOS 4 / 5 : wireshark (CESA-2011:0370)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated wireshark packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Wireshark is a program for monitoring network traffic. Wireshark was
previously known as Ethereal.

A heap-based buffer overflow flaw was found in Wireshark. If Wireshark
opened a specially crafted capture file, it could crash or, possibly,
execute arbitrary code as the user running Wireshark. (CVE-2011-0024)

Several denial of service flaws were found in Wireshark. Wireshark
could crash or stop responding if it read a malformed packet off a
network, or opened a malicious dump file. (CVE-2010-3445,
CVE-2011-0538, CVE-2011-1139, CVE-2011-1140, CVE-2011-1141,
CVE-2011-1143)

Users of Wireshark should upgrade to these updated packages, which
contain backported patches to correct these issues. All running
instances of Wireshark must be restarted for the update to take
effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-April/017403.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?36423823"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-April/017404.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af809564"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-March/017272.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6f9a6ee2"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-March/017273.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a01235e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/23");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"wireshark-1.0.15-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"wireshark-1.0.15-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"wireshark-gnome-1.0.15-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"wireshark-gnome-1.0.15-2.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"wireshark-1.0.15-1.el5_6.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"wireshark-gnome-1.0.15-1.el5_6.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-gnome");
}
