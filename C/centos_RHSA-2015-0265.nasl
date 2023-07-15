#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0265 and 
# CentOS Errata and Security Advisory 2015:0265 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81503);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-0822", "CVE-2015-0827", "CVE-2015-0831", "CVE-2015-0836");
  script_bugtraq_id(72742, 72746, 72755, 72756);
  script_xref(name:"RHSA", value:"2015:0265");

  script_name(english:"CentOS 5 / 6 / 7 : firefox (CESA-2015:0265)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5, 6 and 7.

Red Hat Product Security has rated this update as having Critical
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2015-0836, CVE-2015-0831, CVE-2015-0827)

An information leak flaw was found in the way Firefox implemented
autocomplete forms. An attacker able to trick a user into specifying a
local file in the form could use this flaw to access the contents of
that file. (CVE-2015-0822)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Carsten Book, Christoph Diehl, Gary
Kwong, Jan de Mooij, Liz Henry, Byron Campen, Tom Schuster, Ryan
VanderMeulen, Paul Bandha, Abhishek Arya, and Armin Razmdjou as the
original reporters of these issues.

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 31.5.0 ESR. You can find a link to the
Mozilla advisories in the References section of this erratum.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 31.5.0 ESR, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-February/020946.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?907d6ddb"
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-February/020947.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2aa67940"
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-February/020948.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f4c978c4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0836");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x / 6.x / 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"firefox-31.5.0-1.el5.centos", allowmaj:TRUE)) flag++;

if (rpm_check(release:"CentOS-6", reference:"firefox-31.5.0-1.el6.centos", allowmaj:TRUE)) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"firefox-31.5.0-2.el7.centos", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xulrunner-31.5.0-1.el7.centos", allowmaj:TRUE)) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xulrunner-devel-31.5.0-1.el7.centos", allowmaj:TRUE)) flag++;


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
