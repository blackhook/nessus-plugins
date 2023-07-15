#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0066 and 
# CentOS Errata and Security Advisory 2007:0066 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(24818);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-0456", "CVE-2007-0457", "CVE-2007-0458", "CVE-2007-0459");
  script_xref(name:"RHSA", value:"2007:0066");

  script_name(english:"CentOS 3 / 4 : wireshark (CESA-2007:0066)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New Wireshark packages that fix various security vulnerabilities are
now available. Wireshark was previously known as Ethereal.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

Wireshark is a program for monitoring network traffic.

Several denial of service bugs were found in Wireshark's LLT, IEEE
802.11, http, and tcp protocol dissectors. It was possible for
Wireshark to crash or stop responding if it read a malformed packet
off the network. (CVE-2007-0456, CVE-2007-0457, CVE-2007-0458,
CVE-2007-0459)

Users of Wireshark should upgrade to these updated packages containing
Wireshark version 0.99.5, which is not vulnerable to these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-March/013618.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9033929d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-March/013619.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4761b3ab"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-March/013620.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4629ad61"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-March/013621.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b7f3ef51"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-March/013622.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?10aa4b5f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-March/013623.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3aa6656"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"wireshark-0.99.5-EL3.1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"wireshark-gnome-0.99.5-EL3.1")) flag++;

if (rpm_check(release:"CentOS-4", reference:"wireshark-0.99.5-EL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"wireshark-gnome-0.99.5-EL4.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-gnome");
}
