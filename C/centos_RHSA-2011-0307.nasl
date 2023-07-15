#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0307 and 
# CentOS Errata and Security Advisory 2011:0307 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(52506);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-0564", "CVE-2010-3089", "CVE-2011-0707");
  script_bugtraq_id(27630, 43187, 46464);
  script_xref(name:"RHSA", value:"2011:0307");

  script_name(english:"CentOS 4 / 5 : mailman (CESA-2011:0307)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated mailman package that fixes multiple security issues is now
available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mailman is a program used to help manage email discussion lists.

Multiple input sanitization flaws were found in the way Mailman
displayed usernames of subscribed users on certain pages. If a user
who is subscribed to a mailing list were able to trick a victim into
visiting one of those pages, they could perform a cross-site scripting
(XSS) attack against the victim. (CVE-2011-0707)

Multiple input sanitization flaws were found in the way Mailman
displayed mailing list information. A mailing list administrator could
use this flaw to conduct a cross-site scripting (XSS) attack against
victims viewing a list's 'listinfo' page. (CVE-2008-0564,
CVE-2010-3089)

Red Hat would like to thank Mark Sapiro for reporting the
CVE-2011-0707 and CVE-2010-3089 issues.

Users of mailman should upgrade to this updated package, which
contains backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-April/017371.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e6fa6101"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-April/017372.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ff47f7ed"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-March/017258.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3180c81b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-March/017259.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f9b44361"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mailman package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mailman");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/03");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"mailman-2.1.5.1-34.rhel4.7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"mailman-2.1.5.1-34.rhel4.7")) flag++;

if (rpm_check(release:"CentOS-5", reference:"mailman-2.1.9-6.el5_6.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mailman");
}
