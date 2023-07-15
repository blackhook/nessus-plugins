#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:756 and 
# CentOS Errata and Security Advisory 2005:756 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21853);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-2693");
  script_xref(name:"RHSA", value:"2005:756");

  script_name(english:"CentOS 3 / 4 : cvs (CESA-2005:756)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated cvs package that fixes a security bug is now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

CVS (Concurrent Version System) is a version control system.

An insecure temporary file usage was found in the cvsbug program. It
is possible that a local user could leverage this issue to execute
arbitrary instructions as the user running cvsbug. The Common
Vulnerabilities and Exposures project assigned the name CVE-2005-2693
to this issue.

All users of cvs should upgrade to this updated package, which
includes a patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012111.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7832799e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012112.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5968d782"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012115.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b7a6af1e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012116.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?04088f79"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012120.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bdbcb873"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012122.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3decb83"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cvs package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cvs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", reference:"cvs-1.11.2-28")) flag++;

if (rpm_check(release:"CentOS-4", reference:"cvs-1.11.17-8.RHEL4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cvs");
}
