#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0501 and 
# CentOS Errata and Security Advisory 2007:0501 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25528);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-4168");
  script_bugtraq_id(24461);
  script_xref(name:"RHSA", value:"2007:0501");

  script_name(english:"CentOS 4 / 5 : libexif (CESA-2007:0501)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libexif packages that fix an integer overflow flaw are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The libexif package contains the EXIF library. Applications use this
library to parse EXIF image files.

An integer overflow flaw was found in the way libexif parses EXIF
image tags. If a victim opens a carefully crafted EXIF image file it
could cause the application linked against libexif to execute
arbitrary code or crash. (CVE-2007-4168)

Users of libexif should upgrade to these updated packages, which
contain a backported patch and are not vulnerable to this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013945.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dd708cf8"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013969.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7e472331"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013970.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc90283a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013996.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a766b888"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013997.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f4570fb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libexif packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libexif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libexif-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/18");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", reference:"libexif-0.5.12-5.1.0.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libexif-devel-0.5.12-5.1.0.2")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libexif-0.6.13-4.0.2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libexif-devel-0.6.13-4.0.2.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libexif / libexif-devel");
}
