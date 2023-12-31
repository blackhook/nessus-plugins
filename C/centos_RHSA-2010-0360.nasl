#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0360 and 
# CentOS Errata and Security Advisory 2010:0360 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(45594);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-2560", "CVE-2009-2562", "CVE-2009-2563", "CVE-2009-3550", "CVE-2009-3829", "CVE-2009-4377", "CVE-2010-0304");
  script_bugtraq_id(35748, 36591, 36846, 37407, 37985);
  script_xref(name:"RHSA", value:"2010:0360");

  script_name(english:"CentOS 3 / 4 / 5 : wireshark (CESA-2010:0360)");
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

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Wireshark is a program for monitoring network traffic. Wireshark was
previously known as Ethereal.

An invalid pointer dereference flaw was found in the Wireshark SMB and
SMB2 dissectors. If Wireshark read a malformed packet off a network or
opened a malicious dump file, it could crash or, possibly, execute
arbitrary code as the user running Wireshark. (CVE-2009-4377)

Several buffer overflow flaws were found in the Wireshark LWRES
dissector. If Wireshark read a malformed packet off a network or
opened a malicious dump file, it could crash or, possibly, execute
arbitrary code as the user running Wireshark. (CVE-2010-0304)

Several denial of service flaws were found in Wireshark. Wireshark
could crash or stop responding if it read a malformed packet off a
network, or opened a malicious dump file. (CVE-2009-2560,
CVE-2009-2562, CVE-2009-2563, CVE-2009-3550, CVE-2009-3829)

Users of Wireshark should upgrade to these updated packages, which
contain Wireshark version 1.0.11, and resolve these issues. All
running instances of Wireshark must be restarted for the update to
take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-April/016627.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1304c484"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-April/016628.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e24f164"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-April/016629.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?185cf8bb"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-April/016630.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a3cf0dd0"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-May/016670.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a920d944"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-May/016671.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9c47f79c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Wireshark LWRES Dissector getaddrsbyname_request Buffer Overflow (loop)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"wireshark-1.0.11-EL3.6")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"wireshark-1.0.11-EL3.6")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"wireshark-gnome-1.0.11-EL3.6")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"wireshark-gnome-1.0.11-EL3.6")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"wireshark-1.0.11-1.el4_8.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"wireshark-1.0.11-1.el4_8.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"wireshark-gnome-1.0.11-1.el4_8.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"wireshark-gnome-1.0.11-1.el4_8.5")) flag++;

if (rpm_check(release:"CentOS-5", reference:"wireshark-1.0.11-1.el5_5.5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"wireshark-gnome-1.0.11-1.el5_5.5")) flag++;


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
