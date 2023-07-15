#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0890 and 
# CentOS Errata and Security Advisory 2008:0890 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(34326);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-1070", "CVE-2008-1071", "CVE-2008-1072", "CVE-2008-1561", "CVE-2008-1562", "CVE-2008-1563", "CVE-2008-3137", "CVE-2008-3138", "CVE-2008-3141", "CVE-2008-3145", "CVE-2008-3146", "CVE-2008-3932", "CVE-2008-3933", "CVE-2008-3934");
  script_bugtraq_id(28025, 28485, 30020, 30181, 31009);
  script_xref(name:"RHSA", value:"2008:0890");

  script_name(english:"CentOS 3 / 4 / 5 : wireshark (CESA-2008:0890)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated wireshark packages that fix several security issues are now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Wireshark is a program for monitoring network traffic. Wireshark was
previously known as Ethereal.

Multiple buffer overflow flaws were found in Wireshark. If Wireshark
read a malformed packet off a network, it could crash or, possibly,
execute arbitrary code as the user running Wireshark. (CVE-2008-3146)

Several denial of service flaws were found in Wireshark. Wireshark
could crash or stop responding if it read a malformed packet off a
network, or opened a malformed dump file. (CVE-2008-1070,
CVE-2008-1071, CVE-2008-1072, CVE-2008-1561, CVE-2008-1562,
CVE-2008-1563, CVE-2008-3137, CVE-2008-3138, CVE-2008-3141,
CVE-2008-3145, CVE-2008-3932, CVE-2008-3933, CVE-2008-3934)

Additionally, this update changes the default Pluggable Authentication
Modules (PAM) configuration to always prompt for the root password
before each start of Wireshark. This avoids unintentionally running
Wireshark with root privileges.

Users of wireshark should upgrade to these updated packages, which
contain Wireshark version 1.0.3, and resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015281.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca1ababf"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015282.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8dbb3197"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015283.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ce4d9856"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015284.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f3efc196"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015290.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc966927"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015291.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61878bf6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015297.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eabadb13"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015298.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d42afa4a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 119, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"wireshark-1.0.3-EL3.3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"wireshark-gnome-1.0.3-EL3.3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"wireshark-1.0.3-3.el4_7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"wireshark-1.0.3-3.c4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"wireshark-1.0.3-3.el4_7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"wireshark-gnome-1.0.3-3.el4_7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"wireshark-gnome-1.0.3-3.c4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"wireshark-gnome-1.0.3-3.el4_7")) flag++;

if (rpm_check(release:"CentOS-5", reference:"wireshark-1.0.3-4.el5_2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"wireshark-gnome-1.0.3-4.el5_2")) flag++;


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
