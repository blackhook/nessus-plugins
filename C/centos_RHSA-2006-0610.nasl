#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0610 and 
# CentOS Errata and Security Advisory 2006:0610 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22137);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-2776", "CVE-2006-2778", "CVE-2006-2779", "CVE-2006-2780", "CVE-2006-2782", "CVE-2006-2783", "CVE-2006-2784", "CVE-2006-2785", "CVE-2006-2786", "CVE-2006-2787", "CVE-2006-2788", "CVE-2006-3113", "CVE-2006-3677", "CVE-2006-3801", "CVE-2006-3802", "CVE-2006-3803", "CVE-2006-3805", "CVE-2006-3806", "CVE-2006-3807", "CVE-2006-3808", "CVE-2006-3809", "CVE-2006-3810", "CVE-2006-3811", "CVE-2006-3812");
  script_xref(name:"RHSA", value:"2006:0610");

  script_name(english:"CentOS 4 : Firefox (CESA-2006:0610)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security bugs are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla Firefox is an open source Web browser.

The Mozilla Foundation has discontinued support for the Mozilla
Firefox 1.0 branch. This update deprecates the Mozilla Firefox 1.0
branch in Red Hat Enterprise Linux 4 in favor of the supported Mozilla
Firefox 1.5 branch.

This update also resolves a number of outstanding Firefox security
issues :

Several flaws were found in the way Firefox processed certain
JavaScript actions. A malicious web page could execute arbitrary
JavaScript instructions with the permissions of 'chrome', allowing the
page to steal sensitive information or install browser malware.
(CVE-2006-2776, CVE-2006-2784, CVE-2006-2785, CVE-2006-2787,
CVE-2006-3807, CVE-2006-3809, CVE-2006-3812)

Several denial of service flaws were found in the way Firefox
processed certain web content. A malicious web page could crash the
browser or possibly execute arbitrary code as the user running
Firefox. (CVE-2006-2779, CVE-2006-2780, CVE-2006-3801, CVE-2006-3677,
CVE-2006-3113, CVE-2006-3803, CVE-2006-3805, CVE-2006-3806,
CVE-2006-3811)

A cross-site scripting flaw was found in the way Firefox processed
Unicode Byte-Order-Mark (BOM) markers in UTF-8 web pages. A malicious
web page could execute a script within the browser that a web input
sanitizer could miss due to a malformed 'script' tag. (CVE-2006-2783)

Several flaws were found in the way Firefox processed certain
JavaScript actions. A malicious web page could conduct a cross-site
scripting attack or steal sensitive information (such as cookies owned
by other domains). (CVE-2006-3802, CVE-2006-3810)

A form file upload flaw was found in the way Firefox handled
JavaScript input object mutation. A malicious web page could upload an
arbitrary local file at form submission time without user interaction.
(CVE-2006-2782)

A denial of service flaw was found in the way Firefox called the
crypto.signText() JavaScript function. A malicious web page could
crash the browser if the victim had a client certificate loaded.
(CVE-2006-2778)

Two HTTP response smuggling flaws were found in the way Firefox
processed certain invalid HTTP response headers. A malicious website
could return specially crafted HTTP response headers which may bypass
HTTP proxy restrictions. (CVE-2006-2786)

A flaw was found in the way Firefox processed Proxy AutoConfig
scripts. A malicious Proxy AutoConfig server could execute arbitrary
JavaScript instructions with the permissions of 'chrome', allowing the
page to steal sensitive information or install browser malware.
(CVE-2006-3808)

A double free flaw was found in the way the nsIX509::getRawDER method
was called. If a victim visited a carefully crafted web page, it was
possible to execute arbitrary code as the user running Firefox.
(CVE-2006-2788)

Users of Firefox are advised to upgrade to this update, which contains
Firefox version 1.5.0.5 that corrects these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-July/013071.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?944d3248"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-July/013072.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2fc400b0"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-July/013084.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?deef7c43"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Suite/Firefox Navigator Object Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 94, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-4", reference:"firefox-1.5.0.5-0.el4.1.centos4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
}
