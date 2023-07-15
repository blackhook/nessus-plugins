#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:506 and 
# CentOS Errata and Security Advisory 2005:506 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21835);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2003-0427");
  script_xref(name:"RHSA", value:"2005:506");

  script_name(english:"CentOS 3 / 4 : mikmod (CESA-2005:506)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mikmod packages that fix a security issue are now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

MikMod is a well known MOD music file player for UNIX-based systems.

A buffer overflow bug was found in mikmod during the processing of
archive filenames. An attacker could create a malicious archive that
when opened by mikmod could result in arbitrary code execution. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2003-0427 to this issue.

Users of mikmod are advised to upgrade to these erratum packages,
which contain backported security patches and are not vulnerable to
these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011813.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58aaabd3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011814.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85c8e7b5"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011833.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf1ed3b6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011834.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec70ddaa"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011840.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a31f248"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011845.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?88ed84b7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mikmod packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mikmod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mikmod-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/13");
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
if (rpm_check(release:"CentOS-3", reference:"mikmod-3.1.6-22.EL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mikmod-devel-3.1.6-22.EL3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"mikmod-3.1.6-32.EL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mikmod-devel-3.1.6-32.EL4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mikmod / mikmod-devel");
}
