#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1834 and 
# CentOS Errata and Security Advisory 2015:1834 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86514);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-4500", "CVE-2015-4506", "CVE-2015-4509", "CVE-2015-4511", "CVE-2015-4517", "CVE-2015-4519", "CVE-2015-4520", "CVE-2015-4521", "CVE-2015-4522", "CVE-2015-7174", "CVE-2015-7175", "CVE-2015-7176", "CVE-2015-7177", "CVE-2015-7180");
  script_xref(name:"RHSA", value:"2015:1834");

  script_name(english:"CentOS 5 / 6 / 7 : firefox (CESA-2015:1834)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Critical
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

[Updated 25 August 2014] This erratum previously included an incorrect
list of fixed issues. The issue list has been updated to reflect the
CVEs that were fixed in this update. The firefox packages provided by
this advisory have not been modified in any way.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2015-4500, CVE-2015-4506, CVE-2015-4509,
CVE-2015-4511, CVE-2015-4517, CVE-2015-4521, CVE-2015-4522,
CVE-2015-7174, CVE-2015-7175, CVE-2015-7176, CVE-2015-7177,
CVE-2015-7180)

Two information leak flaws were found in the processing of malformed
web content. A web page containing malicious content could cause
Firefox to disclose sensitive information or, in certain cases, crash.
(CVE-2015-4519, CVE-2015-4520)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Andrew Osmond, Olli Pettay, Andrew
Sutherland, Christian Holler, David Major, Andrew McCreight, Cameron
McCormack, Khalil Zhani, Atte Kettunen, Ronald Crane, Mario Gomes, and
Ehsan Akhgari as the original reporters of these issues.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 38.3.0 ESR, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-September/021414.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f2eae73"
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-September/021415.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd744d77"
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-September/021416.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68cbed3c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4500");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/22");
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
if (rpm_check(release:"CentOS-5", reference:"firefox-38.3.0-2.el5.centos", allowmaj:TRUE)) flag++;

if (rpm_check(release:"CentOS-6", reference:"firefox-38.3.0-2.el6.centos", allowmaj:TRUE)) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"firefox-38.3.0-2.el7.centos", allowmaj:TRUE)) flag++;


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
