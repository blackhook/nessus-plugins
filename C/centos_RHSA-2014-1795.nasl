#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1795 and 
# CentOS Errata and Security Advisory 2014:1795 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78860);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-4337", "CVE-2014-4338");
  script_xref(name:"RHSA", value:"2014:1795");

  script_name(english:"CentOS 7 : cups-filters (CESA-2014:1795)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cups-filters packages that fix two security issues are now
available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The cups-filters package contains backends, filters, and other
software that was once part of the core CUPS distribution but is now
maintained independently.

An out-of-bounds read flaw was found in the way the
process_browse_data() function of cups-browsed handled certain browse
packets. A remote attacker could send a specially crafted browse
packet that, when processed by cups-browsed, would crash the
cups-browsed daemon. (CVE-2014-4337)

A flaw was found in the way the cups-browsed daemon interpreted the
'BrowseAllow' directive in the cups-browsed.conf file. An attacker
able to add a malformed 'BrowseAllow' directive to the
cups-browsed.conf file could use this flaw to bypass intended access
restrictions. (CVE-2014-4338)

All cups-filters users are advised to upgrade to these updated
packages, which contain backported patches to correct these issues.
After installing this update, the cups-browsed daemon will be
restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-November/020734.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f4238ba"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cups-filters packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-4337");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-filters-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-filters-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"cups-filters-1.0.35-15.el7_0.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"cups-filters-devel-1.0.35-15.el7_0.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"cups-filters-libs-1.0.35-15.el7_0.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups-filters / cups-filters-devel / cups-filters-libs");
}
