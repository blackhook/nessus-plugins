#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:789 and 
# CentOS Errata and Security Advisory 2005:789 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21859);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-2701", "CVE-2005-2702", "CVE-2005-2703", "CVE-2005-2704", "CVE-2005-2705", "CVE-2005-2706", "CVE-2005-2707", "CVE-2005-3089");
  script_xref(name:"RHSA", value:"2005:789");

  script_name(english:"CentOS 3 / 4 : Mozilla (CESA-2005:789)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mozilla packages that fix several security bugs are now
available.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor.

A bug was found in the way Mozilla processes XBM image files. If a
user views a specially crafted XBM file, it becomes possible to
execute arbitrary code as the user running Mozilla. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-2701 to this issue.

A bug was found in the way Mozilla processes certain Unicode
sequences. It may be possible to execute arbitrary code as the user
running Mozilla, if the user views a specially crafted Unicode
sequence. (CVE-2005-2702)

A bug was found in the way Mozilla makes XMLHttp requests. It is
possible that a malicious web page could leverage this flaw to exploit
other proxy or server flaws from the victim's machine. It is also
possible that this flaw could be leveraged to send XMLHttp requests to
hosts other than the originator; the default behavior of the browser
is to disallow this. (CVE-2005-2703)

A bug was found in the way Mozilla implemented its XBL interface. It
may be possible for a malicious web page to create an XBL binding in a
way that would allow arbitrary JavaScript execution with chrome
permissions. Please note that in Mozilla 1.7.10 this issue is not
directly exploitable and would need to leverage other unknown
exploits. (CVE-2005-2704)

An integer overflow bug was found in Mozilla's JavaScript engine.
Under favorable conditions, it may be possible for a malicious web
page to execute arbitrary code as the user running Mozilla.
(CVE-2005-2705)

A bug was found in the way Mozilla displays about: pages. It is
possible for a malicious web page to open an about: page, such as
about:mozilla, in such a way that it becomes possible to execute
JavaScript with chrome privileges. (CVE-2005-2706)

A bug was found in the way Mozilla opens new windows. It is possible
for a malicious website to construct a new window without any user
interface components, such as the address bar and the status bar. This
window could then be used to mislead the user for malicious purposes.
(CVE-2005-2707)

Users of Mozilla are advised to upgrade to this updated package that
contains Mozilla version 1.7.12 and is not vulnerable to these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012178.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a96e06b4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012179.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98cef9b8"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012180.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?56d9aa88"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012183.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ec3b1cb"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012191.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2466e4ab"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012192.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8fbdff82"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mozilla packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(94);

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/22");
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
if (rpm_check(release:"CentOS-3", reference:"mozilla-1.7.12-1.1.3.2.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-chat-1.7.12-1.1.3.2.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-devel-1.7.12-1.1.3.2.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-dom-inspector-1.7.12-1.1.3.2.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-js-debugger-1.7.12-1.1.3.2.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-mail-1.7.12-1.1.3.2.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-nspr-1.7.12-1.1.3.2.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-nspr-devel-1.7.12-1.1.3.2.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-nss-1.7.12-1.1.3.2.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-nss-devel-1.7.12-1.1.3.2.centos3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"devhelp-0.9.2-2.4.7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"devhelp-0.9.2-2.4.7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"devhelp-devel-0.9.2-2.4.7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"devhelp-devel-0.9.2-2.4.7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-1.7.12-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-chat-1.7.12-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-devel-1.7.12-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-dom-inspector-1.7.12-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-js-debugger-1.7.12-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-mail-1.7.12-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-nspr-1.7.12-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-nspr-devel-1.7.12-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-nss-1.7.12-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-nss-devel-1.7.12-1.4.1.centos4")) flag++;


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
