#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0129 and 
# CentOS Errata and Security Advisory 2006:0129 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21978);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-3351");
  script_xref(name:"RHSA", value:"2006:0129");

  script_name(english:"CentOS 4 : spamassassin (CESA-2006:0129)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated spamassassin package that fixes a denial of service flaw is
now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

SpamAssassin provides a way to reduce unsolicited commercial email
(SPAM) from incoming email.

A denial of service bug was found in SpamAssassin. An attacker could
construct a message in such a way that would cause SpamAssassin to
crash. If a number of these messages are sent, it could lead to a
denial of service, potentially preventing the delivery or filtering of
email. The Common Vulnerabilities and Exposures project
(cve.mitre.org) assigned the name CVE-2005-3351 to this issue.

The following issues have also been fixed in this update :

* service spamassassin restart sometimes fails * Content Boundary '--'
throws off message parser * sa-learn: massive memory usage on large
messages * High memory usage with many newlines * service spamassassin
messages not translated * Numerous other bug fixes that improve spam
filter accuracy and safety

Users of SpamAssassin should upgrade to this updated package
containing version 3.0.5, which is not vulnerable to these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-March/012703.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?25165338"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-March/012729.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?145d6fa9"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-March/012736.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d7b96179"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected spamassassin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spamassassin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", reference:"spamassassin-3.0.5-3.el4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "spamassassin");
}
