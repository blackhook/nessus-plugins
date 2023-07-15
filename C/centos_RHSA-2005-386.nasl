#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:386 and 
# CentOS Errata and Security Advisory 2005:386 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21931);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-0989", "CVE-2005-1153", "CVE-2005-1154", "CVE-2005-1155", "CVE-2005-1156", "CVE-2005-1157", "CVE-2005-1159", "CVE-2005-1160");
  script_xref(name:"RHSA", value:"2005:386");

  script_name(english:"CentOS 4 : mozilla (CESA-2005:386)");
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

This update has been rated as having Important security impact by the
Red Hat Security Response Team.

Mozilla is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor.

Vladimir V. Perepelitsa discovered a bug in the way Mozilla handles
anonymous functions during regular expression string replacement. It
is possible for a malicious web page to capture a random block of
browser memory. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-0989 to this issue.

Doron Rosenberg discovered a bug in the way Mozilla displays pop-up
windows. If a user choses to open a pop-up window whose URL is
malicious JavaScript, the script will be executed with elevated
privileges. (CVE-2005-1153)

A bug was found in the way Mozilla handles the JavaScript global scope
for a window. It is possible for a malicious web page to define a
global variable known to be used by a different site, allowing
malicious code to be executed in the context of the site.
(CVE-2005-1154)

Michael Krax discovered a bug in the way Mozilla handles favicon
links. A malicious web page can programatically define a favicon link
tag as JavaScript, executing arbitrary JavaScript with elevated
privileges. (CVE-2005-1155)

Michael Krax discovered a bug in the way Mozilla installed search
plugins. If a user chooses to install a search plugin from a malicious
site, the new plugin could silently overwrite an existing plugin. This
could allow the malicious plugin to execute arbitrary code and stealm
sensitive information. (CVE-2005-1156 CVE-2005-1157)

A bug was found in the way Mozilla validated several XPInstall related
JavaScript objects. A malicious web page could pass other objects to
the XPInstall objects, resulting in the JavaScript interpreter jumping
to arbitrary locations in memory. (CVE-2005-1159)

A bug was found in the way the Mozilla privileged UI code handled DOM
nodes from the content window. A malicious web page could install
malicious JavaScript code or steal data requiring a user to do
commonplace actions such as clicking a link or opening the context
menu. (CVE-2005-1160)

Users of Mozilla are advised to upgrade to this updated package which
contains Mozilla version 1.7.7 to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-April/011603.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?44b6c934"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-April/011604.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?77fb8a0d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mozilla packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/26");
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
if (rpm_check(release:"CentOS-4", reference:"mozilla-1.7.7-1.4.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-chat-1.7.7-1.4.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-devel-1.7.7-1.4.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-dom-inspector-1.7.7-1.4.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-js-debugger-1.7.7-1.4.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-mail-1.7.7-1.4.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-nspr-1.7.7-1.4.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-nspr-devel-1.7.7-1.4.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-nss-1.7.7-1.4.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-nss-devel-1.7.7-1.4.2.centos4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla / mozilla-chat / mozilla-devel / mozilla-dom-inspector / etc");
}
