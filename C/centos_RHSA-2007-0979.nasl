#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0979 and 
# CentOS Errata and Security Advisory 2007:0979 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(27540);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-1095", "CVE-2007-2292", "CVE-2007-3511", "CVE-2007-3844", "CVE-2007-5334", "CVE-2007-5337", "CVE-2007-5338", "CVE-2007-5339", "CVE-2007-5340");
  script_bugtraq_id(22688, 23668, 24725, 25142, 26132);
  script_xref(name:"RHSA", value:"2007:0979");

  script_name(english:"CentOS 4 / 5 : firefox (CESA-2007:0979)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security bugs are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla Firefox is an open source Web browser.

Several flaws were found in the way in which Firefox processed certain
malformed web content. A web page containing malicious content could
cause Firefox to crash or potentially execute arbitrary code as the
user running Firefox. (CVE-2007-5338, CVE-2007-5339, CVE-2007-5340)

Several flaws were found in the way in which Firefox displayed
malformed web content. A web page containing specially crafted content
could potentially trick a user into surrendering sensitive
information. (CVE-2007-1095, CVE-2007-3844, CVE-2007-3511,
CVE-2007-5334)

A flaw was found in the Firefox sftp protocol handler. A malicious web
page could access data from a remote sftp site, possibly stealing
sensitive user data. (CVE-2007-5337)

A request-splitting flaw was found in the way in which Firefox
generates a digest authentication request. If a user opened a
specially crafted URL, it was possible to perform cross-site scripting
attacks, web cache poisoning, or other, similar exploits.
(CVE-2007-2292)

All users of Firefox are advised to upgrade to these updated packages,
which contain backported patches that correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014309.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d344ed3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014310.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7acb63ff"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014313.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8c8318c7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014316.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?301d3d54"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014317.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c86dfe1c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 20, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/25");
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
if (rpm_check(release:"CentOS-4", reference:"firefox-1.5.0.12-0.7.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"firefox-1.5.0.12-6.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"firefox-devel-1.5.0.12-6.el5.centos")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / firefox-devel");
}
