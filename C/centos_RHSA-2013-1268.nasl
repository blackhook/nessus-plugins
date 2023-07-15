#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1268 and 
# CentOS Errata and Security Advisory 2013:1268 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(69936);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-1718", "CVE-2013-1722", "CVE-2013-1725", "CVE-2013-1730", "CVE-2013-1732", "CVE-2013-1735", "CVE-2013-1736", "CVE-2013-1737");
  script_bugtraq_id(62463, 62467, 62478, 62479);
  script_xref(name:"RHSA", value:"2013:1268");

  script_name(english:"CentOS 5 / 6 : firefox (CESA-2013:1268)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2013-1718, CVE-2013-1722, CVE-2013-1725,
CVE-2013-1730, CVE-2013-1732, CVE-2013-1735, CVE-2013-1736)

A flaw was found in the way Firefox handled certain DOM JavaScript
objects. An attacker could use this flaw to make JavaScript client or
add-on code make incorrect, security sensitive decisions.
(CVE-2013-1737)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Andre Bargull, Scoobidiver, Bobby
Holley, Reuben Morais, Abhishek Arya, Ms2ger, Sachin Shinde, Aki
Helin, Nils, and Boris Zbarsky as the original reporters of these
issues.

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 17.0.9 ESR. You can find a link to the
Mozilla advisories in the References section of this erratum.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 17.0.9 ESR, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-September/019941.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a0b5bf8"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-September/019943.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?550dd7a6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1718");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x / 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"firefox-17.0.9-1.el5.centos", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-17.0.9-1.el5_9", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-17.0.9-1.el5_9", allowmaj:TRUE)) flag++;

if (rpm_check(release:"CentOS-6", reference:"firefox-17.0.9-1.el6.centos", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-6", reference:"xulrunner-17.0.9-1.el6.centos", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-6", reference:"xulrunner-devel-17.0.9-1.el6.centos", allowmaj:TRUE)) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / xulrunner / xulrunner-devel");
}
