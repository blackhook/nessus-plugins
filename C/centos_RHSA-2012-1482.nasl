#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1482 and 
# CentOS Errata and Security Advisory 2012:1482 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63005);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-4201", "CVE-2012-4202", "CVE-2012-4207", "CVE-2012-4209", "CVE-2012-4210", "CVE-2012-4214", "CVE-2012-4215", "CVE-2012-4216", "CVE-2012-5829", "CVE-2012-5830", "CVE-2012-5833", "CVE-2012-5835", "CVE-2012-5839", "CVE-2012-5840", "CVE-2012-5841", "CVE-2012-5842");
  script_bugtraq_id(56607, 56628, 56633);
  script_xref(name:"RHSA", value:"2012:1482");

  script_name(english:"CentOS 5 / 6 : firefox (CESA-2012:1482)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Updated firefox packages that fix several security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2012-4214, CVE-2012-4215, CVE-2012-4216,
CVE-2012-5829, CVE-2012-5830, CVE-2012-5833, CVE-2012-5835,
CVE-2012-5839, CVE-2012-5840, CVE-2012-5842)

A buffer overflow flaw was found in the way Firefox handled GIF
(Graphics Interchange Format) images. A web page containing a
malicious GIF image could cause Firefox to crash or, possibly, execute
arbitrary code with the privileges of the user running Firefox.
(CVE-2012-4202)

A flaw was found in the way the Style Inspector tool in Firefox
handled certain Cascading Style Sheets (CSS). Running the tool (Tools
-> Web Developer -> Inspect) on malicious CSS could result in the
execution of HTML and CSS content with chrome privileges.
(CVE-2012-4210)

A flaw was found in the way Firefox decoded the HZ-GB-2312 character
encoding. A web page containing malicious content could cause Firefox
to run JavaScript code with the permissions of a different website.
(CVE-2012-4207)

A flaw was found in the location object implementation in Firefox.
Malicious content could possibly use this flaw to allow restricted
content to be loaded by plug-ins. (CVE-2012-4209)

A flaw was found in the way cross-origin wrappers were implemented.
Malicious content could use this flaw to perform cross-site scripting
attacks. (CVE-2012-5841)

A flaw was found in the evalInSandbox implementation in Firefox.
Malicious content could use this flaw to perform cross-site scripting
attacks. (CVE-2012-4201)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 10.0.11 ESR. You can find a link to
the Mozilla advisories in the References section of this erratum.

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Abhishek Arya, miaubiz, Jesse Ruderman,
Andrew McCreight, Bob Clary, Kyle Huey, Atte Kettunen, Mariusz
Mlynski, Masato Kinugawa, Bobby Holley, and moz_bug_r_a4 as the
original reporters of these issues.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 10.0.11 ESR, which corrects these issues.
After installing the update, Firefox must be restarted for the changes
to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-November/019003.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b021398c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-November/019006.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e907e0b9"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4214");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/23");
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
if (rpm_check(release:"CentOS-5", reference:"firefox-10.0.11-1.el5.centos", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-10.0.11-1.el5_8", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-10.0.11-1.el5_8", allowmaj:TRUE)) flag++;

if (rpm_check(release:"CentOS-6", reference:"firefox-10.0.11-1.el6.centos", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-6", reference:"xulrunner-10.0.11-1.el6.centos", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-6", reference:"xulrunner-devel-10.0.11-1.el6.centos", allowmaj:TRUE)) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / xulrunner / xulrunner-devel");
}
