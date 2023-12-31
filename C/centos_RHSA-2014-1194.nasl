#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1194 and 
# CentOS Errata and Security Advisory 2014:1194 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77989);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-5485", "CVE-2012-5486", "CVE-2012-5488", "CVE-2012-5497", "CVE-2012-5498", "CVE-2012-5499", "CVE-2012-5500", "CVE-2013-6496", "CVE-2014-3521");
  script_bugtraq_id(56341, 69820, 69830);
  script_xref(name:"RHSA", value:"2014:1194");

  script_name(english:"CentOS 5 : conga (CESA-2014:1194)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated conga packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 5.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The Conga project is a management system for remote workstations. It
consists of luci, which is a secure web-based front end, and ricci,
which is a secure daemon that dispatches incoming messages to
underlying management modules.

It was discovered that Plone, included as a part of luci, did not
properly protect the administrator interface (control panel). A remote
attacker could use this flaw to inject a specially crafted Python
statement or script into Plone's restricted Python sandbox that, when
the administrator interface was accessed, would be executed with the
privileges of that administrator user. (CVE-2012-5485)

It was discovered that Plone, included as a part of luci, did not
properly sanitize HTTP headers provided within certain URL requests. A
remote attacker could use a specially crafted URL that, when
processed, would cause the injected HTTP headers to be returned as a
part of the Plone HTTP response, potentially allowing the attacker to
perform other more advanced attacks. (CVE-2012-5486)

Multiple information leak flaws were found in the way conga processed
luci site extension-related URL requests. A remote, unauthenticated
attacker could issue a specially crafted HTTP request that, when
processed, would result in unauthorized information disclosure.
(CVE-2013-6496)

It was discovered that various components in the luci site
extension-related URLs were not properly restricted to administrative
users. A remote, authenticated attacker could escalate their
privileges to perform certain actions that should be restricted to
administrative users, such as adding users and systems, and viewing
log data. (CVE-2014-3521)

It was discovered that Plone, included as a part of luci, did not
properly protect the privilege of running RestrictedPython scripts. A
remote attacker could use a specially crafted URL that, when
processed, would allow the attacker to submit and perform expensive
computations or, in conjunction with other attacks, be able to access
or alter privileged information. (CVE-2012-5488)

It was discovered that Plone, included as a part of luci, did not
properly enforce permissions checks on the membership database. A
remote attacker could use a specially crafted URL that, when
processed, could allow the attacker to enumerate user account names.
(CVE-2012-5497)

It was discovered that Plone, included as a part of luci, did not
properly handle the processing of requests for certain collections. A
remote attacker could use a specially crafted URL that, when
processed, would lead to excessive I/O and/or cache resource
consumption. (CVE-2012-5498)

It was discovered that Plone, included as a part of luci, did not
properly handle the processing of very large values passed to an
internal utility function. A remote attacker could use a specially
crafted URL that, when processed, would lead to excessive memory
consumption. (CVE-2012-5499)

It was discovered that Plone, included as a part of luci, allowed a
remote anonymous user to change titles of content items due to
improper permissions checks. (CVE-2012-5500)

The CVE-2014-3521 issue was discovered by Radek Steiger of Red Hat,
and the CVE-2013-6496 issue was discovered by Jan Pokorny of Red Hat.

In addition, these updated conga packages include several bug fixes.
Space precludes documenting all of these changes in this advisory.
Users are directed to the Red Hat Enterprise Linux 5.11 Technical
Notes, linked to in the References section, for information on the
most significant of these changes

All conga users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing this update, the luci and ricci services will be restarted
automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-September/020611.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c2762c18"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected conga packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5485");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:luci");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ricci");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"luci-0.12.2-81.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ricci-0.12.2-81.el5.centos")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "luci / ricci");
}
