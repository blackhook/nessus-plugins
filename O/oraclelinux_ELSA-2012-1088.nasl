#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:1088 and 
# Oracle Linux Security Advisory ELSA-2012-1088 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68578);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-1948", "CVE-2012-1950", "CVE-2012-1951", "CVE-2012-1952", "CVE-2012-1953", "CVE-2012-1954", "CVE-2012-1955", "CVE-2012-1957", "CVE-2012-1958", "CVE-2012-1959", "CVE-2012-1961", "CVE-2012-1962", "CVE-2012-1963", "CVE-2012-1964", "CVE-2012-1965", "CVE-2012-1966", "CVE-2012-1967");
  script_xref(name:"RHSA", value:"2012:1088");

  script_name(english:"Oracle Linux 5 / 6 : firefox (ELSA-2012-1088)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"From Red Hat Security Advisory 2012:1088 :

Updated firefox packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

A web page containing malicious content could cause Firefox to crash
or, potentially, execute arbitrary code with the privileges of the
user running Firefox. (CVE-2012-1948, CVE-2012-1951, CVE-2012-1952,
CVE-2012-1953, CVE-2012-1954, CVE-2012-1958, CVE-2012-1962,
CVE-2012-1967)

A malicious web page could bypass same-compartment security wrappers
(SCSW) and execute arbitrary code with chrome privileges.
(CVE-2012-1959)

A flaw in the context menu functionality in Firefox could allow a
malicious website to bypass intended restrictions and allow a
cross-site scripting attack. (CVE-2012-1966)

A page different to that in the address bar could be displayed when
dragging and dropping to the address bar, possibly making it easier
for a malicious site or user to perform a phishing attack.
(CVE-2012-1950)

A flaw in the way Firefox called history.forward and history.back
could allow an attacker to conceal a malicious URL, possibly tricking
a user into believing they are viewing a trusted site. (CVE-2012-1955)

A flaw in a parser utility class used by Firefox to parse feeds (such
as RSS) could allow an attacker to execute arbitrary JavaScript with
the privileges of the user running Firefox. This issue could have
affected other browser components or add-ons that assume the class
returns sanitized input. (CVE-2012-1957)

A flaw in the way Firefox handled X-Frame-Options headers could allow
a malicious website to perform a clickjacking attack. (CVE-2012-1961)

A flaw in the way Content Security Policy (CSP) reports were generated
by Firefox could allow a malicious web page to steal a victim's OAuth
2.0 access tokens and OpenID credentials. (CVE-2012-1963)

A flaw in the way Firefox handled certificate warnings could allow a
man-in-the-middle attacker to create a crafted warning, possibly
tricking a user into accepting an arbitrary certificate as trusted.
(CVE-2012-1964)

A flaw in the way Firefox handled feed:javascript URLs could allow
output filtering to be bypassed, possibly leading to a cross-site
scripting attack. (CVE-2012-1965)

The nss update RHBA-2012:0337 for Red Hat Enterprise Linux 5 and 6
introduced a mitigation for the CVE-2011-3389 flaw. For compatibility
reasons, it remains disabled by default in the nss packages. This
update makes Firefox enable the mitigation by default. It can be
disabled by setting the NSS_SSL_CBC_RANDOM_IV environment variable to
0 before launching Firefox. (BZ#838879)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 10.0.6 ESR. You can find a link to the
Mozilla advisories in the References section of this erratum.

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Benoit Jacob, Jesse Ruderman, Christian
Holler, Bill McCloskey, Abhishek Arya, Arthur Gerkis, Bill Keese,
moz_bug_r_a4, Bobby Holley, Code Audit Labs, Mariusz Mlynski, Mario
Heiderich, Frederic Buclin, Karthikeyan Bhargavan, Matt McCutchen,
Mario Gomes, and Soroush Dalili as the original reporters of these
issues.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 10.0.6 ESR, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-July/002939.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-July/002944.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"firefox-10.0.6-1.0.1.el5_8", allowmaj:TRUE)) flag++;
if (rpm_check(release:"EL5", reference:"xulrunner-10.0.6-2.0.1.el5_8")) flag++;
if (rpm_check(release:"EL5", reference:"xulrunner-devel-10.0.6-2.0.1.el5_8")) flag++;

if (rpm_check(release:"EL6", reference:"firefox-10.0.6-1.0.1.el6_3", allowmaj:TRUE)) flag++;
if (rpm_check(release:"EL6", reference:"xulrunner-10.0.6-1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"xulrunner-devel-10.0.6-1.0.1.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / xulrunner / xulrunner-devel");
}
