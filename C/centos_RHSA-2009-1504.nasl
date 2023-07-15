#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1504 and 
# CentOS Errata and Security Advisory 2009:1504 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43804);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-3603", "CVE-2009-3607", "CVE-2009-3608", "CVE-2009-3609");
  script_xref(name:"RHSA", value:"2009:1504");

  script_name(english:"CentOS 5 : poppler (CESA-2009:1504)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated poppler packages that fix multiple security issues and a bug
are now available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Poppler is a Portable Document Format (PDF) rendering library, used by
applications such as Evince.

Multiple integer overflow flaws were found in poppler. An attacker
could create a malicious PDF file that would cause applications that
use poppler (such as Evince) to crash or, potentially, execute
arbitrary code when opened. (CVE-2009-3603, CVE-2009-3608,
CVE-2009-3609)

Red Hat would like to thank Chris Rohlf for reporting the
CVE-2009-3608 issue.

This update also corrects a regression introduced in the previous
poppler security update, RHSA-2009:0480, that prevented poppler from
rendering certain PDF documents correctly. (BZ#528147)

Users are advised to upgrade to these updated packages, which contain
backported patches to resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-October/016268.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?41096fc6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-October/016271.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08fab85d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected poppler packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
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
if (rpm_check(release:"CentOS-5", reference:"poppler-0.5.4-4.4.el5_4.11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"poppler-devel-0.5.4-4.4.el5_4.11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"poppler-utils-0.5.4-4.4.el5_4.11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "poppler / poppler-devel / poppler-utils");
}
