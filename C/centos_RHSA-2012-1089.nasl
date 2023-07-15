#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1089 and 
# CentOS Errata and Security Advisory 2012:1089 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59999);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-1948", "CVE-2012-1951", "CVE-2012-1952", "CVE-2012-1953", "CVE-2012-1954", "CVE-2012-1955", "CVE-2012-1957", "CVE-2012-1958", "CVE-2012-1959", "CVE-2012-1961", "CVE-2012-1962", "CVE-2012-1963", "CVE-2012-1964", "CVE-2012-1967");
  script_xref(name:"RHSA", value:"2012:1089");

  script_name(english:"CentOS 5 / 6 : thunderbird (CESA-2012:1089)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An updated thunderbird package that fixes multiple security issues is
now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the processing of malformed content.
Malicious content could cause Thunderbird to crash or, potentially,
execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2012-1948, CVE-2012-1951, CVE-2012-1952,
CVE-2012-1953, CVE-2012-1954, CVE-2012-1958, CVE-2012-1962,
CVE-2012-1967)

Malicious content could bypass same-compartment security wrappers
(SCSW) and execute arbitrary code with chrome privileges.
(CVE-2012-1959)

A flaw in the way Thunderbird called history.forward and history.back
could allow an attacker to conceal a malicious URL, possibly tricking
a user into believing they are viewing trusted content.
(CVE-2012-1955)

A flaw in a parser utility class used by Thunderbird to parse feeds
(such as RSS) could allow an attacker to execute arbitrary JavaScript
with the privileges of the user running Thunderbird. This issue could
have affected other Thunderbird components or add-ons that assume the
class returns sanitized input. (CVE-2012-1957)

A flaw in the way Thunderbird handled X-Frame-Options headers could
allow malicious content to perform a clickjacking attack.
(CVE-2012-1961)

A flaw in the way Content Security Policy (CSP) reports were generated
by Thunderbird could allow malicious content to steal a victim's OAuth
2.0 access tokens and OpenID credentials. (CVE-2012-1963)

A flaw in the way Thunderbird handled certificate warnings could allow
a man-in-the-middle attacker to create a crafted warning, possibly
tricking a user into accepting an arbitrary certificate as trusted.
(CVE-2012-1964)

The nss update RHBA-2012:0337 for Red Hat Enterprise Linux 5 and 6
introduced a mitigation for the CVE-2011-3389 flaw. For compatibility
reasons, it remains disabled by default in the nss packages. This
update makes Thunderbird enable the mitigation by default. It can be
disabled by setting the NSS_SSL_CBC_RANDOM_IV environment variable to
0 before launching Thunderbird. (BZ#838879)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Benoit Jacob, Jesse Ruderman, Christian
Holler, Bill McCloskey, Abhishek Arya, Arthur Gerkis, Bill Keese,
moz_bug_r_a4, Bobby Holley, Mariusz Mlynski, Mario Heiderich, Frederic
Buclin, Karthikeyan Bhargavan, and Matt McCutchen as the original
reporters of these issues.

Note: None of the issues in this advisory can be exploited by a
specially crafted HTML mail message as JavaScript is disabled by
default for mail messages. They could be exploited another way in
Thunderbird, for example, when viewing the full remote content of an
RSS feed.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 10.0.6 ESR, which corrects these issues.
After installing the update, Thunderbird must be restarted for the
changes to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-July/018745.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?63b8dece"
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-July/018748.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6ac2b36a"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-1951");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", reference:"thunderbird-10.0.6-1.el5.centos", allowmaj:TRUE)) flag++;

if (rpm_check(release:"CentOS-6", reference:"thunderbird-10.0.6-1.el6.centos", allowmaj:TRUE)) flag++;


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
