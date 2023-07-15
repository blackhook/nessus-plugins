#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1126 and 
# CentOS Errata and Security Advisory 2009:1126 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43762);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-1303", "CVE-2009-1305", "CVE-2009-1306", "CVE-2009-1307", "CVE-2009-1308", "CVE-2009-1309", "CVE-2009-1392", "CVE-2009-1833", "CVE-2009-1836", "CVE-2009-1838", "CVE-2009-2210");
  script_bugtraq_id(35370, 35372, 35380, 35383);
  script_xref(name:"RHSA", value:"2009:1126");

  script_name(english:"CentOS 5 : thunderbird (CESA-2009:1126)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated thunderbird package that fixes several security issues is
now available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the processing of malformed HTML mail
content. An HTML mail message containing malicious content could cause
Thunderbird to crash or, potentially, execute arbitrary code as the
user running Thunderbird. (CVE-2009-1392, CVE-2009-1303,
CVE-2009-1305, CVE-2009-1833, CVE-2009-1838)

Several flaws were found in the way malformed HTML mail content was
processed. An HTML mail message containing malicious content could
execute arbitrary JavaScript in the context of the mail message,
possibly presenting misleading data to the user, or stealing sensitive
information such as login credentials. (CVE-2009-1306, CVE-2009-1307,
CVE-2009-1308, CVE-2009-1309)

A flaw was found in the way Thunderbird handled error responses
returned from proxy servers. If an attacker is able to conduct a
man-in-the-middle attack against a Thunderbird instance that is using
a proxy server, they may be able to steal sensitive information from
the site Thunderbird is displaying. (CVE-2009-1836)

Note: JavaScript support is disabled by default in Thunderbird. None
of the above issues are exploitable unless JavaScript is enabled.

All Thunderbird users should upgrade to this updated package, which
resolves these issues. All running instances of Thunderbird must be
restarted for the update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-June/016011.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?69762b07"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-June/016012.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?50ba5d40"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(16, 20, 79, 94, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/26");
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
if (rpm_check(release:"CentOS-5", reference:"thunderbird-2.0.0.22-2.el5.centos")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
