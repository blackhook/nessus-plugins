#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:1028 and 
# Oracle Linux Security Advisory ELSA-2008-1028 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67775);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-1722", "CVE-2008-5286");
  script_bugtraq_id(32518);
  script_xref(name:"RHSA", value:"2008:1028");

  script_name(english:"Oracle Linux 3 : cups (ELSA-2008-1028)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:1028 :

Updated cups packages that fix a security issue are now available for
Red Hat Enterprise Linux 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Common UNIX(r) Printing System (CUPS) provides a portable printing
layer for UNIX operating systems.

An integer overflow flaw, leading to a heap buffer overflow, was
discovered in the Portable Network Graphics (PNG) decoding routines
used by the CUPS image-converting filters, 'imagetops' and
'imagetoraster'. An attacker could create a malicious PNG file that
could, potentially, execute arbitrary code as the 'lp' user if the
file was printed. (CVE-2008-5286)

CUPS users should upgrade to these updated packages, which contain a
backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-December/000833.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"cups-1.1.17-13.3.55")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"cups-1.1.17-13.3.55")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"cups-devel-1.1.17-13.3.55")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"cups-devel-1.1.17-13.3.55")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"cups-libs-1.1.17-13.3.55")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"cups-libs-1.1.17-13.3.55")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-devel / cups-libs");
}
