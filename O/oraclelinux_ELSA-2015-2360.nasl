#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:2360 and 
# Oracle Linux Security Advisory ELSA-2015-2360 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87035);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-3258", "CVE-2015-3279");
  script_xref(name:"RHSA", value:"2015:2360");

  script_name(english:"Oracle Linux 7 : cups-filters (ELSA-2015-2360)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:2360 :

Updated cups-filters packages that fix two security issues, several
bugs, and add one enhancement are now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The cups-filters packages contain back ends, filters, and other
software that was once part of the core Common UNIX Printing System
(CUPS) distribution but is now maintained independently.

A heap-based buffer overflow flaw and an integer overflow flaw leading
to a heap-based buffer overflow were discovered in the way the
texttopdf utility of cups-filter processed print jobs with a specially
crafted line size. An attacker able to submit print jobs could use
these flaws to crash texttopdf or, possibly, execute arbitrary code
with the privileges of the 'lp' user. (CVE-2015-3258, CVE-2015-3279)

The CVE-2015-3258 issue was discovered by Petr Sklenar of Red Hat.

Notably, this update also fixes the following bug :

* Previously, when polling CUPS printers from a CUPS server, when a
printer name contained an underscore (_), the client displayed the
name containing a hyphen (-) instead. This made the print queue
unavailable. With this update, CUPS allows the underscore character in
printer names, and printers appear as shown on the CUPS server as
expected. (BZ#1167408)

In addition, this update adds the following enhancement :

* Now, the information from local and remote CUPS servers is cached
during each poll, and the CUPS server load is reduced. (BZ#1191691)

All cups-filters users are advised to upgrade to these updated
packages, which contain backported patches to correct these issues and
add this enhancement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-November/005570.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cups-filters packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups-filters-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups-filters-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"cups-filters-1.0.35-21.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"cups-filters-devel-1.0.35-21.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"cups-filters-libs-1.0.35-21.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups-filters / cups-filters-devel / cups-filters-libs");
}
