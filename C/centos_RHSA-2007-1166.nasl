#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:1166 and 
# CentOS Errata and Security Advisory 2007:1166 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(29753);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-6352");
  script_bugtraq_id(26942);
  script_xref(name:"RHSA", value:"2007:1166");

  script_name(english:"CentOS 4 : libexif (CESA-2007:1166)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libexif packages that fix a security issue are now available
for Red Hat Enterprise Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The libexif packages contain the Exif library. Exif is an image file
format specification that enables metadata tags to be added to
existing JPEG, TIFF and RIFF files. The Exif library makes it possible
to parse an Exif file and read this metadata.

An integer overflow flaw was found in the way libexif parses Exif
image tags. If a victim opens a carefully crafted Exif image file, it
could cause the application linked against libexif to execute
arbitrary code, or crash. (CVE-2007-6352)

Users of libexif are advised to upgrade to these updated packages,
which contain a backported patch to resolve this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-December/014527.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f3a94c1"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-December/014543.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4bae7747"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-December/014544.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?478df900"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libexif packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libexif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libexif-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/24");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libexif-0.5.12-5.1.0.2.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libexif-0.5.12-5.1.0.2.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libexif-0.5.12-5.1.0.2.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libexif-devel-0.5.12-5.1.0.2.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libexif-devel-0.5.12-5.1.0.2.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libexif-devel-0.5.12-5.1.0.2.el4_6.1")) flag++;


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
