#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:435 and 
# CentOS Errata and Security Advisory 2005:435 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21827);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-1476", "CVE-2005-1477", "CVE-2005-1531", "CVE-2005-1532");
  script_xref(name:"RHSA", value:"2005:435");

  script_name(english:"CentOS 3 / 4 : mozilla (CESA-2005:435)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mozilla packages that fix various security bugs are now
available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

[Updated 24 May 2005] This erratum now includes updated devhelp
packages which are required to satisfy a dependency on systems that
have devhelp packages installed.

Mozilla is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor.

Several bugs were found in the way Mozilla executes JavaScript code.
JavaScript executed from a web page should run with a restricted
access level, preventing dangerous actions. It is possible that a
malicious web page could execute JavaScript code with elevated
privileges, allowing access to protected data and functions. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the names CVE-2005-1476, CVE-2005-1477, CVE-2005-1531, and
CVE-2005-1532 to these issues.

Users of Mozilla are advised to upgrade to this updated package, which
contains Mozilla version 1.7.8 to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011738.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?355b36ce"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011739.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ad1530b3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011743.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?408c0c61"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011744.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ff2a9392"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011750.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2fb16e5d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011751.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08b8ff13"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mozilla packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-chat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"mozilla-1.7.8-1.1.3.1.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-chat-1.7.8-1.1.3.1.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-devel-1.7.8-1.1.3.1.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-dom-inspector-1.7.8-1.1.3.1.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-js-debugger-1.7.8-1.1.3.1.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-mail-1.7.8-1.1.3.1.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-nspr-1.7.8-1.1.3.1.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-nspr-devel-1.7.8-1.1.3.1.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-nss-1.7.8-1.1.3.1.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-nss-devel-1.7.8-1.1.3.1.centos3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"devhelp-0.9.2-2.4.4.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"devhelp-0.9.2-2.4.4.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"devhelp-devel-0.9.2-2.4.4.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"devhelp-devel-0.9.2-2.4.4.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-1.7.8-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-chat-1.7.8-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-devel-1.7.8-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-dom-inspector-1.7.8-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-js-debugger-1.7.8-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-mail-1.7.8-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-nspr-1.7.8-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-nspr-devel-1.7.8-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-nss-1.7.8-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-nss-devel-1.7.8-1.4.1.centos4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devhelp / devhelp-devel / mozilla / mozilla-chat / mozilla-devel / etc");
}
