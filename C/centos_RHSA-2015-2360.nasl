#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2360 and 
# CentOS Errata and Security Advisory 2015:2360 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87152);
  script_version("2.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-3258", "CVE-2015-3279");
  script_xref(name:"RHSA", value:"2015:2360");

  script_name(english:"CentOS 7 : cups-filters (CESA-2015:2360)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cups-filters packages that fix two security issues, several
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
  # https://lists.centos.org/pipermail/centos-cr-announce/2015-November/002181.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7e73baac"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cups-filters packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3258");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-filters-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-filters-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/02");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"cups-filters-1.0.35-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"cups-filters-devel-1.0.35-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"cups-filters-libs-1.0.35-21.el7")) flag++;


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
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups-filters / cups-filters-devel / cups-filters-libs");
}
