#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0860 and 
# CentOS Errata and Security Advisory 2007:0860 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25949);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-4131");
  script_bugtraq_id(25417);
  script_xref(name:"RHSA", value:"2007:0860");

  script_name(english:"CentOS 4 / 5 : tar (CESA-2007:0860)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tar package that fixes a path traversal flaw is now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The GNU tar program saves many files together in one archive and can
restore individual files (or all of the files) from that archive.

A path traversal flaw was discovered in the way GNU tar extracted
archives. A malicious user could create a tar archive that could write
to arbitrary files to which the user running GNU tar had write access.
(CVE-2007-4131)

Red Hat would like to thank Dmitry V. Levin for reporting this issue.

Users of tar should upgrade to this updated package, which contains a
replacement backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-August/014149.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3821c664"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-August/014151.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c615b1a6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-August/014152.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?030d6296"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-August/014153.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3ad8267"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-August/014154.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34b093c0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tar package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tar");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/28");
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
if (rpm_check(release:"CentOS-4", reference:"tar-1.14-12.5.1.RHEL4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"tar-1.15.1-23.0.1.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tar");
}
