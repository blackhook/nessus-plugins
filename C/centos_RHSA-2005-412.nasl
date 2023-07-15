#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:412 and 
# CentOS Errata and Security Advisory 2005:412 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21820);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-0605");
  script_xref(name:"RHSA", value:"2005:412");

  script_name(english:"CentOS 3 / 4 : openmotif (CESA-2005:412)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openmotif packages that fix a flaw in the Xpm image library
are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

OpenMotif provides libraries which implement the Motif industry
standard graphical user interface.

An integer overflow flaw was found in libXpm, which is used to decode
XPM (X PixMap) images. A vulnerable version of this library was found
within OpenMotif. An attacker could create a carefully crafted XPM
file which would cause an application to crash or potentially execute
arbitrary code if opened by a victim. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2005-0605
to this issue.

Users of OpenMotif are advised to upgrade to these erratum packages,
which contains a backported security patch to the embedded libXpm
library."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011645.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8c0d3d9a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011646.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2bd8b3b9"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011649.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?09c2ada1"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011655.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48ea683c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011656.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f153f6e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openmotif packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openmotif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openmotif-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openmotif21");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/11");
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
if (rpm_check(release:"CentOS-3", reference:"openmotif-2.2.3-5.RHEL3.2")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openmotif-devel-2.2.3-5.RHEL3.2")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openmotif21-2.1.30-9.RHEL3.6")) flag++;

if (rpm_check(release:"CentOS-4", reference:"openmotif-2.2.3-9.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openmotif-devel-2.2.3-9.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openmotif21-2.1.30-11.RHEL4.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openmotif / openmotif-devel / openmotif21");
}
