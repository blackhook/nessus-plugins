#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0400 and 
# CentOS Errata and Security Advisory 2007:0400 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(36608);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-1362", "CVE-2007-1562", "CVE-2007-2867", "CVE-2007-2868", "CVE-2007-2869", "CVE-2007-2870", "CVE-2007-2871");
  script_bugtraq_id(23082, 24242);
  script_xref(name:"RHSA", value:"2007:0400");

  script_name(english:"CentOS 4 / 5 : devhelp / firefox / yelp (CESA-2007:0400)");
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

Several flaws were found in the way Firefox processed certain
malformed JavaScript code. A web page containing malicious JavaScript
code could cause Firefox to crash or potentially execute arbitrary
code as the user running Firefox. (CVE-2007-2867, CVE-2007-2868)

A flaw was found in the way Firefox handled certain FTP PASV commands.
A malicious FTP server could use this flaw to perform a rudimentary
port-scan of machines behind a user's firewall. (CVE-2007-1562)

Several denial of service flaws were found in the way Firefox handled
certain form and cookie data. A malicious website that is able to set
arbitrary form and cookie data could prevent Firefox from functioning
properly. (CVE-2007-1362, CVE-2007-2869)

A flaw was found in the way Firefox handled the addEventListener
JavaScript method. A malicious website could use this method to access
or modify sensitive data from another website. (CVE-2007-2870)

A flaw was found in the way Firefox displayed certain web content. A
malicious web page could generate content that would overlay user
interface elements such as the hostname and security indicators,
tricking users into thinking they are visiting a different site.
(CVE-2007-2871)

Users of Firefox are advised to upgrade to these erratum packages,
which contain Firefox version 1.5.0.12 that corrects these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013854.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a30f446"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013859.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f584c57"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013860.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e1195591"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013861.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76bc5218"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013862.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?35025cbf"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013863.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9326b0fe"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013864.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f710d12d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013841.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1f6bd4e3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013842.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aada3429"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected devhelp, firefox and / or yelp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 94, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-4", reference:"firefox-1.5.0.12-0.1.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"devhelp-0.12-11.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"devhelp-devel-0.12-11.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"firefox-1.5.0.12-1.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"firefox-devel-1.5.0.12-1.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"yelp-2.16.0-15.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devhelp / devhelp-devel / firefox / firefox-devel / yelp");
}
