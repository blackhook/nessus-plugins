#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1104 and 
# CentOS Errata and Security Advisory 2011:1104 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56268);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-2690", "CVE-2011-2692");
  script_bugtraq_id(48660);
  script_xref(name:"RHSA", value:"2011:1104");

  script_name(english:"CentOS 5 : libpng (CESA-2011:1104)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libpng packages that fix two security issues are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The libpng packages contain a library of functions for creating and
manipulating PNG (Portable Network Graphics) image format files.

A buffer overflow flaw was found in the way libpng processed certain
PNG image files. An attacker could create a specially crafted PNG
image that, when opened, could cause an application using libpng to
crash or, potentially, execute arbitrary code with the privileges of
the user running the application. (CVE-2011-2690)

Note: The application behavior required to exploit CVE-2011-2690 is
rarely used. No application shipped with Red Hat Enterprise Linux
behaves this way, for example.

An uninitialized memory read issue was found in the way libpng
processed certain PNG images that use the Physical Scale (sCAL)
extension. An attacker could create a specially crafted PNG image
that, when opened, could cause an application using libpng to crash.
(CVE-2011-2692)

Users of libpng should upgrade to these updated packages, which
contain backported patches to correct these issues. All running
applications using libpng must be restarted for the update to take
effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017876.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7c60d873"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017877.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27a3bff0"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2011-September/000240.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db3de6b6"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2011-September/000241.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4dbacfe5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpng packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/23");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"libpng-1.2.10-7.1.el5_7.5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpng-devel-1.2.10-7.1.el5_7.5")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpng / libpng-devel");
}
