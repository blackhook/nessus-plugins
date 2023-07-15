#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0427 and 
# CentOS Errata and Security Advisory 2006:0427 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21995);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-1931");
  script_bugtraq_id(17645);
  script_xref(name:"RHSA", value:"2006:0427");

  script_name(english:"CentOS 4 : ruby (CESA-2006:0427)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ruby packages that fix a denial of service issue are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Ruby is an interpreted scripting language for object-oriented
programming.

A bug was found in the way Ruby creates its xmlrpc and http servers.
The servers use a non blocking socket, which enables a remote user to
cause a denial of service condition if they are able to transmit a
large volume of information from the network server. (CVE-2006-1931)

Users of Ruby should update to these erratum packages, which contain a
backported patch and are not vulnerable to this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-May/012892.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b3625a04"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-May/012893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?30ff2d37"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-May/012903.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6ec3d4b4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", reference:"irb-1.8.1-7.EL4.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ruby-1.8.1-7.EL4.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ruby-devel-1.8.1-7.EL4.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ruby-docs-1.8.1-7.EL4.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ruby-libs-1.8.1-7.EL4.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ruby-mode-1.8.1-7.EL4.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ruby-tcltk-1.8.1-7.EL4.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "irb / ruby / ruby-devel / ruby-docs / ruby-libs / ruby-mode / etc");
}
