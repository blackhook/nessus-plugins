#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0625 and 
# CentOS Errata and Security Advisory 2010:0625 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(48409);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-1455", "CVE-2010-2283", "CVE-2010-2284", "CVE-2010-2286", "CVE-2010-2287", "CVE-2010-2994", "CVE-2010-2995");
  script_bugtraq_id(39950, 40728);
  script_xref(name:"RHSA", value:"2010:0625");

  script_name(english:"CentOS 4 / 5 : wireshark (CESA-2010:0625)");
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

Multiple buffer overflow flaws were found in the Wireshark SigComp
Universal Decompressor Virtual Machine (UDVM) dissector. If Wireshark
read a malformed packet off a network or opened a malicious dump file,
it could crash or, possibly, execute arbitrary code as the user
running Wireshark. (CVE-2010-2287, CVE-2010-2995)

Several denial of service flaws were found in Wireshark. Wireshark
could crash or stop responding if it read a malformed packet off a
network, or opened a malicious dump file. (CVE-2010-1455,
CVE-2010-2283, CVE-2010-2284, CVE-2010-2286)

Users of Wireshark should upgrade to these updated packages, which
contain Wireshark version 1.0.15, and resolve these issues. All
running instances of Wireshark must be restarted for the update to
take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-August/016932.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ea3370a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-August/016933.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17af990f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-August/016956.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?18b151ef"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-August/016957.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0687cae5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/24");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"wireshark-1.0.15-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"wireshark-1.0.15-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"wireshark-gnome-1.0.15-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"wireshark-gnome-1.0.15-1.el4_8.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"wireshark-1.0.15-1.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"wireshark-gnome-1.0.15-1.el5_5.1")) flag++;


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
