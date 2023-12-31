#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0755 and 
# CentOS Errata and Security Advisory 2010:0755 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(49814);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-3609", "CVE-2010-3702", "CVE-2010-3703", "CVE-2010-3704");
  script_bugtraq_id(36703);
  script_xref(name:"RHSA", value:"2010:0755");

  script_name(english:"CentOS 4 : cups (CESA-2010:0755)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cups packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The Common UNIX Printing System (CUPS) provides a portable printing
layer for UNIX operating systems. The CUPS 'pdftops' filter converts
Portable Document Format (PDF) files to PostScript.

Multiple flaws were discovered in the CUPS 'pdftops' filter. An
attacker could create a malicious PDF file that, when printed, would
cause 'pdftops' to crash or, potentially, execute arbitrary code as
the 'lp' user. (CVE-2010-3702, CVE-2009-3609)

Users of cups are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
this update, the cupsd daemon will be restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-October/017051.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7297673f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-October/017052.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eaf7cd4a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/11");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cups-1.1.22-0.rc1.9.32.el4.10")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cups-1.1.22-0.rc1.9.32.el4.10")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cups-devel-1.1.22-0.rc1.9.32.el4.10")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cups-devel-1.1.22-0.rc1.9.32.el4.10")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cups-libs-1.1.22-0.rc1.9.32.el4.10")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cups-libs-1.1.22-0.rc1.9.32.el4.10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-devel / cups-libs");
}
