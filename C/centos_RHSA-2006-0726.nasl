#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0726 and 
# CentOS Errata and Security Advisory 2006:0726 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(36335);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-4574", "CVE-2006-4805", "CVE-2006-5468", "CVE-2006-5469", "CVE-2006-5740");
  script_bugtraq_id(20762);
  script_xref(name:"RHSA", value:"2006:0726");

  script_name(english:"CentOS 3 / 4 : wireshark (CESA-2006:0726)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New Wireshark packages that fix various security vulnerabilities are
now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Wireshark is a program for monitoring network traffic.

Several flaws were found in Wireshark's HTTP, WBXML, LDAP, and XOT
protocol dissectors. Wireshark could crash or stop responding if it
read a malformed packet off the network. (CVE-2006-4805,
CVE-2006-5468, CVE-2006-5469, CVE-2006-5740)

A single NULL byte heap based buffer overflow was found in Wireshark's
MIME Multipart dissector. Wireshark could crash or possibly execute
arbitrary arbitrary code as the user running Wireshark.
(CVE-2006-4574)

Users of Wireshark should upgrade to these updated packages containing
Wireshark version 0.99.4, which is not vulnerable to these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-November/013377.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e94c9a5b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-November/013391.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb086be0"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-November/013392.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b15ea4a5"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-November/013393.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7668141e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-November/013395.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc70a9ee"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-November/013396.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1bab976d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", reference:"wireshark-0.99.4-EL3.1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"wireshark-gnome-0.99.4-EL3.1")) flag++;

if (rpm_check(release:"CentOS-4", reference:"wireshark-0.99.4-EL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"wireshark-gnome-0.99.4-EL4.1")) flag++;


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
