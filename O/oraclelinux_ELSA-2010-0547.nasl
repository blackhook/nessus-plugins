#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0547 and 
# Oracle Linux Security Advisory ELSA-2010-0547 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68068);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-0654", "CVE-2010-1205", "CVE-2010-1206", "CVE-2010-1207", "CVE-2010-1208", "CVE-2010-1209", "CVE-2010-1210", "CVE-2010-1211", "CVE-2010-1212", "CVE-2010-1213", "CVE-2010-1214", "CVE-2010-1215", "CVE-2010-2751", "CVE-2010-2752", "CVE-2010-2753", "CVE-2010-2754", "CVE-2010-2760");
  script_bugtraq_id(41055, 41174, 41824);
  script_xref(name:"RHSA", value:"2010:0547");

  script_name(english:"Oracle Linux 4 / 5 : firefox (ELSA-2010-0547)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0547 :

Updated firefox packages that fix several security issues are now
available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2010-1208, CVE-2010-1209, CVE-2010-1211,
CVE-2010-1212, CVE-2010-1214, CVE-2010-1215, CVE-2010-2752,
CVE-2010-2753)

A memory corruption flaw was found in the way Firefox decoded certain
PNG images. An attacker could create a specially crafted PNG image
that, when opened, could cause Firefox to crash or, potentially,
execute arbitrary code with the privileges of the user running
Firefox. (CVE-2010-1205)

Several same-origin policy bypass flaws were found in Firefox. An
attacker could create a malicious web page that, when viewed by a
victim, could steal private data from a different website the victim
has loaded with Firefox. (CVE-2010-0654, CVE-2010-1207, CVE-2010-1213,
CVE-2010-2754)

A flaw was found in the way Firefox presented the location bar to a
user. A malicious website could trick a user into thinking they are
visiting the site reported by the location bar, when the page is
actually content controlled by an attacker. (CVE-2010-1206)

A flaw was found in the way Firefox displayed the location bar when
visiting a secure web page. A malicious server could use this flaw to
present data that appears to originate from a secure server, even
though it does not. (CVE-2010-2751)

A flaw was found in the way Firefox displayed certain malformed
characters. A malicious web page could use this flaw to bypass certain
string sanitization methods, allowing it to display malicious
information to users. (CVE-2010-1210)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 3.6.7. You can find a link to the
Mozilla advisories in the References section of this erratum.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 3.6.7, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-July/001547.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-July/001549.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/22");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"firefox-3.6.7-2.0.1.el4")) flag++;

if (rpm_check(release:"EL5", reference:"firefox-3.6.7-2.0.1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"xulrunner-1.9.2.7-2.0.1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"xulrunner-devel-1.9.2.7-2.0.1.el5")) flag++;


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
