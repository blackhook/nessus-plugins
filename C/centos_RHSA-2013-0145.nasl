#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0145 and 
# CentOS Errata and Security Advisory 2013:0145 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63432);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-0744", "CVE-2013-0746", "CVE-2013-0748", "CVE-2013-0750", "CVE-2013-0753", "CVE-2013-0754", "CVE-2013-0758", "CVE-2013-0759", "CVE-2013-0762", "CVE-2013-0766", "CVE-2013-0767", "CVE-2013-0769");
  script_bugtraq_id(57185);
  script_xref(name:"RHSA", value:"2013:0145");

  script_name(english:"CentOS 5 / 6 : thunderbird (CESA-2013:0145)");
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
Thunderbird. (CVE-2013-0744, CVE-2013-0746, CVE-2013-0750,
CVE-2013-0753, CVE-2013-0754, CVE-2013-0762, CVE-2013-0766,
CVE-2013-0767, CVE-2013-0769)

A flaw was found in the way Chrome Object Wrappers were implemented.
Malicious content could be used to cause Thunderbird to execute
arbitrary code via plug-ins installed in Thunderbird. (CVE-2013-0758)

A flaw in the way Thunderbird displayed URL values could allow
malicious content or a user to perform a phishing attack.
(CVE-2013-0759)

An information disclosure flaw was found in the way certain JavaScript
functions were implemented in Thunderbird. An attacker could use this
flaw to bypass Address Space Layout Randomization (ASLR) and other
security restrictions. (CVE-2013-0748)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Atte Kettunen, Boris Zbarsky, pa_kt,
regenrecht, Abhishek Arya, Christoph Diehl, Christian Holler, Mats
Palmgren, Chiaki Ishikawa, Mariusz Mlynski, Masato Kinugawa, and Jesse
Ruderman as the original reporters of these issues.

Note: All issues except CVE-2013-0744, CVE-2013-0753, and
CVE-2013-0754 cannot be exploited by a specially crafted HTML mail
message as JavaScript is disabled by default for mail messages. They
could be exploited another way in Thunderbird, for example, when
viewing the full remote content of an RSS feed.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 10.0.12 ESR, which corrects these issues.
After installing the update, Thunderbird must be restarted for the
changes to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-January/019049.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f6f9b40e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-January/019201.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c1d1c8ba"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-January/000465.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb9636f6"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0750");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 17.0.1 Flash Privileged Code Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/09");
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
if (rpm_check(release:"CentOS-5", reference:"thunderbird-10.0.12-3.el5.centos", allowmaj:TRUE)) flag++;

if (rpm_check(release:"CentOS-6", reference:"thunderbird-10.0.12-3.el6.centos", allowmaj:TRUE)) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
