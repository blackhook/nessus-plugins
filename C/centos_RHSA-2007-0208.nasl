#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0208 and 
# CentOS Errata and Security Advisory 2007:0208 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67040);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-3183");
  script_xref(name:"RHSA", value:"2007:0208");

  script_name(english:"CentOS 4 : w3c-libwww (CESA-2007:0208)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated w3c-libwww packages that fix a security issue and a bug are
now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

w3c-libwww is a general-purpose web library.

Several buffer overflow flaws in w3c-libwww were found. If a client
application that uses w3c-libwww connected to a malicious HTTP server,
it could trigger an out of bounds memory access, causing the client
application to crash (CVE-2005-3183).

This updated version of w3c-libwww also fixes an issue when computing
MD5 sums on a 64 bit machine.

Users of w3c-libwww should upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013711.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6199f57"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected w3c-libwww packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:w3c-libwww");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:w3c-libwww-apps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:w3c-libwww-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"w3c-libwww-5.4.0-10.1.RHEL4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"w3c-libwww-apps-5.4.0-10.1.RHEL4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"w3c-libwww-devel-5.4.0-10.1.RHEL4.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "w3c-libwww / w3c-libwww-apps / w3c-libwww-devel");
}
