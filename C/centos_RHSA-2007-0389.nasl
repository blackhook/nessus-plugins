#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0389 and 
# CentOS Errata and Security Advisory 2007:0389 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25354);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-1995");
  script_bugtraq_id(23417);
  script_xref(name:"RHSA", value:"2007:0389");

  script_name(english:"CentOS 3 / 4 / 5 : quagga (CESA-2007:0389)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated quagga package that fixes a security bug is now available
for Red Hat Enterprise Linux 3, 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Quagga is a TCP/IP based routing software suite.

An out of bounds memory read flaw was discovered in Quagga's bgpd. A
configured peer of bgpd could cause Quagga to crash, leading to a
denial of service (CVE-2007-1995).

All users of Quagga should upgrade to this updated package, which
contains a backported patch to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013825.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?887667e3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013826.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?617cf6bd"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013827.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b60bd935"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013828.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e0cd5064"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013829.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?da5996bc"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013830.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?598b7f94"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013837.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1794d7ba"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013838.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33f969ed"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected quagga packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:quagga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:quagga-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:quagga-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/01");
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
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"quagga-0.96.2-12.3E")) flag++;
if (rpm_check(release:"CentOS-3", reference:"quagga-contrib-0.96.2-12.3E")) flag++;
if (rpm_check(release:"CentOS-3", reference:"quagga-devel-0.96.2-12.3E")) flag++;

if (rpm_check(release:"CentOS-4", reference:"quagga-0.98.3-2.4.0.1.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"quagga-contrib-0.98.3-2.4.0.1.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"quagga-devel-0.98.3-2.4.0.1.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"quagga-0.98.6-2.1.0.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"quagga-contrib-0.98.6-2.1.0.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"quagga-devel-0.98.6-2.1.0.1.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "quagga / quagga-contrib / quagga-devel");
}
