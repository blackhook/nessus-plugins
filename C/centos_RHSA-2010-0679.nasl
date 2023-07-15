#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0679 and 
# CentOS Errata and Security Advisory 2010:0679 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(49204);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-4889", "CVE-2010-2059", "CVE-2010-2199");
  script_bugtraq_id(40512);
  script_xref(name:"RHSA", value:"2010:0679");

  script_name(english:"CentOS 5 : rpm (CESA-2010:0679)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rpm packages that fix one security issue and one bug are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The RPM Package Manager (RPM) is a command line driven package
management system capable of installing, uninstalling, verifying,
querying, and updating software packages.

It was discovered that RPM did not remove setuid and setgid bits set
on binaries when upgrading packages. A local attacker able to create
hard links to binaries could use this flaw to keep those binaries on
the system, at a specific version level and with the setuid or setgid
bit set, even if the package providing them was upgraded by a system
administrator. This could have security implications if a package was
upgraded because of a security flaw in a setuid or setgid program.
(CVE-2010-2059)

This update also fixes the following bug :

* A memory leak in the communication between RPM and the
Security-Enhanced Linux (SELinux) subsystem, which could have caused
extensive memory consumption. In reported cases, this issue was
triggered by running rhn_check when errata were scheduled to be
applied. (BZ#627630)

All users of rpm are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-September/016978.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b3c1326d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-September/016979.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e4b5e10"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected rpm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:popt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/13");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"popt-1.10.2.3-20.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"rpm-4.4.2.3-20.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"rpm-apidocs-4.4.2.3-20.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"rpm-build-4.4.2.3-20.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"rpm-devel-4.4.2.3-20.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"rpm-libs-4.4.2.3-20.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"rpm-python-4.4.2.3-20.el5_5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "popt / rpm / rpm-apidocs / rpm-build / rpm-devel / rpm-libs / etc");
}
