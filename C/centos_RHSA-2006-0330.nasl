#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0330 and 
# CentOS Errata and Security Advisory 2006:0330 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21994);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-0292", "CVE-2006-0296", "CVE-2006-0748", "CVE-2006-0749", "CVE-2006-0884", "CVE-2006-1045", "CVE-2006-1724", "CVE-2006-1727", "CVE-2006-1728", "CVE-2006-1730", "CVE-2006-1731", "CVE-2006-1732", "CVE-2006-1733", "CVE-2006-1734", "CVE-2006-1735", "CVE-2006-1737", "CVE-2006-1738", "CVE-2006-1739", "CVE-2006-1741", "CVE-2006-1742", "CVE-2006-1790");
  script_xref(name:"RHSA", value:"2006:0330");

  script_name(english:"CentOS 4 : thunderbird (CESA-2006:0330)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated thunderbird packages that fix various bugs are now available
for Red Hat Enterprise Linux 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

[Updated 24 Apr 2006] The erratum text has been updated to include the
details of additional issues that were fixed by these erratum packages
but which were not public at the time of release. No changes have been
made to the packages.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several bugs were found in the way Thunderbird processes malformed
JavaScript. A malicious HTML mail message could modify the content of
a different open HTML mail message, possibly stealing sensitive
information or conducting a cross-site scripting attack. Please note
that JavaScript support is disabled by default in Thunderbird.
(CVE-2006-1731, CVE-2006-1732, CVE-2006-1741)

Several bugs were found in the way Thunderbird processes certain
JavaScript actions. A malicious HTML mail message could execute
arbitrary JavaScript instructions with the permissions of 'chrome',
allowing the page to steal sensitive information or install browser
malware. Please note that JavaScript support is disabled by default in
Thunderbird. (CVE-2006-0292, CVE-2006-0296, CVE-2006-1727,
CVE-2006-1728, CVE-2006-1733, CVE-2006-1734, CVE-2006-1735,
CVE-2006-1742)

Several bugs were found in the way Thunderbird processes malformed
HTML mail messages. A carefully crafted malicious HTML mail message
could cause the execution of arbitrary code as the user running
Thunderbird. (CVE-2006-0748, CVE-2006-0749, CVE-2006-1724,
CVE-2006-1730, CVE-2006-1737, CVE-2006-1738, CVE-2006-1739,
CVE-2006-1790)

A bug was found in the way Thunderbird processes certain inline
content in HTML mail messages. It may be possible for a remote
attacker to send a carefully crafted mail message to the victim, which
will fetch remote content, even if Thunderbird is configured not to
fetch remote content. (CVE-2006-1045)

A bug was found in the way Thunderbird executes in-line mail
forwarding. If a user can be tricked into forwarding a maliciously
crafted mail message as in-line content, it is possible for the
message to execute JavaScript with the permissions of 'chrome'.
(CVE-2006-0884)

Users of Thunderbird are advised to upgrade to these updated packages
containing Thunderbird version 1.0.8, which is not vulnerable to these
issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-April/012835.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?411b3ba2"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-April/012837.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de246f51"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-April/012838.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dd8c7f71"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 79, 119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/21");
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
if (rpm_check(release:"CentOS-4", reference:"thunderbird-1.0.8-1.4.1.centos4")) flag++;


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
