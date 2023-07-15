#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2594 and 
# CentOS Errata and Security Advisory 2015:2594 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87283);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-7981", "CVE-2015-8126", "CVE-2015-8472");
  script_xref(name:"RHSA", value:"2015:2594");

  script_name(english:"CentOS 6 : libpng (CESA-2015:2594)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libpng packages that fix three security issues are now
available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The libpng packages contain a library of functions for creating and
manipulating PNG (Portable Network Graphics) image format files.

It was discovered that the png_get_PLTE() and png_set_PLTE() functions
of libpng did not correctly calculate the maximum palette sizes for
bit depths of less than 8. In case an application tried to use these
functions in combination with properly calculated palette sizes, this
could lead to a buffer overflow or out-of-bounds reads. An attacker
could exploit this to cause a crash or potentially execute arbitrary
code by tricking an unsuspecting user into processing a specially
crafted PNG image. However, the exact impact is dependent on the
application using the library. (CVE-2015-8126, CVE-2015-8472)

An array-indexing error was discovered in the png_convert_to_rfc1123()
function of libpng. An attacker could possibly use this flaw to cause
an out-of-bounds read by tricking an unsuspecting user into processing
a specially crafted PNG image. (CVE-2015-7981)

All libpng users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-December/021517.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?105323c0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpng packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8126");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"libpng-1.2.49-2.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libpng-devel-1.2.49-2.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libpng-static-1.2.49-2.el6_7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpng / libpng-devel / libpng-static");
}
