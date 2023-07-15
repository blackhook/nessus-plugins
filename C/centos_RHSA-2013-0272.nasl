#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0272 and 
# CentOS Errata and Security Advisory 2013:0272 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(64729);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-0775", "CVE-2013-0776", "CVE-2013-0780", "CVE-2013-0782", "CVE-2013-0783");
  script_xref(name:"RHSA", value:"2013:0272");

  script_name(english:"CentOS 5 / 6 : thunderbird (CESA-2013:0272)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An updated thunderbird package that fixes several security issues is
now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the processing of malformed content.
Malicious content could cause Thunderbird to crash or, potentially,
execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2013-0775, CVE-2013-0780, CVE-2013-0782,
CVE-2013-0783)

It was found that, after canceling a proxy server's authentication
prompt, the address bar continued to show the requested site's
address. An attacker could use this flaw to conduct phishing attacks
by tricking a user into believing they are viewing trusted content.
(CVE-2013-0776)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Nils, Abhishek Arya, Olli Pettay,
Christoph Diehl, Gary Kwong, Jesse Ruderman, Andrew McCreight, Joe
Drew, Wayne Mery, and Michal Zalewski as the original reporters of
these issues.

Note: All issues cannot be exploited by a specially crafted HTML mail
message as JavaScript is disabled by default for mail messages. They
could be exploited another way in Thunderbird, for example, when
viewing the full remote content of an RSS feed.

Important: This erratum upgrades Thunderbird to version 17.0.3 ESR.
Thunderbird 17 is not completely backwards-compatible with all Mozilla
add-ons and Thunderbird plug-ins that worked with Thunderbird 10.0.
Thunderbird 17 checks compatibility on first-launch, and, depending on
the individual configuration and the installed add-ons and plug-ins,
may disable said Add-ons and plug-ins, or attempt to check for updates
and upgrade them. Add-ons and plug-ins may have to be manually
updated.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 17.0.3 ESR, which corrects these issues.
After installing the update, Thunderbird must be restarted for the
changes to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-February/019246.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fea23fdd"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-February/019251.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6d3da7b6"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0775");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/21");
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
if (rpm_check(release:"CentOS-5", reference:"thunderbird-17.0.3-1.el5.centos", allowmaj:TRUE)) flag++;

if (rpm_check(release:"CentOS-6", reference:"thunderbird-17.0.3-1.el6.centos", allowmaj:TRUE)) flag++;


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
