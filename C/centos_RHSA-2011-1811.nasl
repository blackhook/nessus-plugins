#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1811 and 
# CentOS Errata and Security Advisory 2011:1811 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(57140);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-4274", "CVE-2011-4516", "CVE-2011-4517");
  script_bugtraq_id(38164, 50992);
  script_xref(name:"RHSA", value:"2011:1811");

  script_name(english:"CentOS 4 / 5 : netpbm (CESA-2011:1811)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated netpbm packages that fix three security issues are now
available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The netpbm packages contain a library of functions which support
programs for handling various graphics file formats, including .pbm
(Portable Bit Map), .pgm (Portable Gray Map), .pnm (Portable Any Map),
.ppm (Portable Pixel Map), and others.

Two heap-based buffer overflow flaws were found in the embedded JasPer
library, which is used to provide support for Part 1 of the JPEG 2000
image compression standard in the jpeg2ktopam and pamtojpeg2k tools.
An attacker could create a malicious JPEG 2000 compressed image file
that could cause jpeg2ktopam to crash or, potentially, execute
arbitrary code with the privileges of the user running jpeg2ktopam.
These flaws do not affect pamtojpeg2k. (CVE-2011-4516, CVE-2011-4517)

A stack-based buffer overflow flaw was found in the way the xpmtoppm
tool processed X PixMap (XPM) image files. An attacker could create a
malicious XPM file that would cause xpmtoppm to crash or, potentially,
execute arbitrary code with the privileges of the user running
xpmtoppm. (CVE-2009-4274)

Red Hat would like to thank Jonathan Foote of the CERT Coordination
Center for reporting the CVE-2011-4516 and CVE-2011-4517 issues.

All users of netpbm are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-December/018319.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f19815f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-December/018320.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5dfe54de"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-December/018321.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75088498"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-December/018322.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?81a9fe4f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected netpbm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:netpbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:netpbm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:netpbm-progs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"netpbm-10.35.58-8.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"netpbm-10.35.58-8.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"netpbm-devel-10.35.58-8.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"netpbm-devel-10.35.58-8.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"netpbm-progs-10.35.58-8.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"netpbm-progs-10.35.58-8.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"netpbm-10.35.58-8.el5_7.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"netpbm-devel-10.35.58-8.el5_7.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"netpbm-progs-10.35.58-8.el5_7.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "netpbm / netpbm-devel / netpbm-progs");
}
