#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0887 and 
# CentOS Errata and Security Advisory 2011:0887 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(55405);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-0083", "CVE-2011-0085", "CVE-2011-2362", "CVE-2011-2363", "CVE-2011-2364", "CVE-2011-2365", "CVE-2011-2371", "CVE-2011-2373", "CVE-2011-2374", "CVE-2011-2375", "CVE-2011-2376", "CVE-2011-2377", "CVE-2011-2605");
  script_xref(name:"RHSA", value:"2011:0887");

  script_name(english:"CentOS 4 / 5 : thunderbird (CESA-2011:0887)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated thunderbird package that fixes several security issues is
now available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Thunderbird is a standalone mail and newsgroup client.

A flaw was found in the way Thunderbird handled malformed JPEG images.
An HTML mail message containing a malicious JPEG image could cause
Thunderbird to crash or, potentially, execute arbitrary code with the
privileges of the user running Thunderbird. (CVE-2011-2377)

Multiple dangling pointer flaws were found in Thunderbird. Malicious
HTML content could cause Thunderbird to crash or, potentially, execute
arbitrary code with the privileges of the user running Thunderbird.
(CVE-2011-0083, CVE-2011-0085, CVE-2011-2363)

Several flaws were found in the processing of malformed HTML content.
Malicious HTML content could cause Thunderbird to crash or,
potentially, execute arbitrary code with the privileges of the user
running Thunderbird. (CVE-2011-2364, CVE-2011-2365, CVE-2011-2374,
CVE-2011-2375, CVE-2011-2376)

An integer overflow flaw was found in the way Thunderbird handled
JavaScript Array objects. Malicious content could cause Thunderbird to
execute JavaScript with the privileges of the user running
Thunderbird. (CVE-2011-2371)

A use-after-free flaw was found in the way Thunderbird handled
malformed JavaScript. Malicious content could cause Thunderbird to
execute JavaScript with the privileges of the user running
Thunderbird. (CVE-2011-2373)

It was found that Thunderbird could treat two separate cookies (for
web content) as interchangeable if both were for the same domain name
but one of those domain names had a trailing '.' character. This
violates the same-origin policy and could possibly lead to data being
leaked to the wrong domain. (CVE-2011-2362)

All Thunderbird users should upgrade to this updated package, which
resolves these issues. All running instances of Thunderbird must be
restarted for the update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-August/017681.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74dad046"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-August/017682.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5dc71820"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-June/017623.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9c69fbc7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-June/017624.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2bd5cdac"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Firefox Array.reduceRight() Integer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"thunderbird-1.5.0.12-39.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"thunderbird-1.5.0.12-39.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"thunderbird-2.0.0.24-18.el5.centos")) flag++;


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
