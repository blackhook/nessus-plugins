#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:601 and 
# CentOS Errata and Security Advisory 2005:601 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21952);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-0989", "CVE-2005-1159", "CVE-2005-1160", "CVE-2005-1532", "CVE-2005-2261", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2269", "CVE-2005-2270");
  script_xref(name:"RHSA", value:"2005:601");

  script_name(english:"CentOS 4 : thunderbird (CESA-2005:601)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated thunderbird package that fixes various bugs is now available
for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Mozilla Thunderbird is a standalone mail and newsgroup client.

A bug was found in the way Thunderbird handled anonymous functions
during regular expression string replacement. It is possible for a
malicious HTML mail to capture a random block of client memory. The
Common Vulnerabilities and Exposures project has assigned this bug the
name CVE-2005-0989.

A bug was found in the way Thunderbird validated several XPInstall
related JavaScript objects. A malicious HTML mail could pass other
objects to the XPInstall objects, resulting in the JavaScript
interpreter jumping to arbitrary locations in memory. (CVE-2005-1159)

A bug was found in the way the Thunderbird privileged UI code handled
DOM nodes from the content window. An HTML message could install
malicious JavaScript code or steal data when a user performs
commonplace actions such as clicking a link or opening the context
menu. (CVE-2005-1160)

A bug was found in the way Thunderbird executed JavaScript code.
JavaScript executed from HTML mail should run with a restricted access
level, preventing dangerous actions. It is possible that a malicious
HTML mail could execute JavaScript code with elevated privileges,
allowing access to protected data and functions. (CVE-2005-1532)

A bug was found in the way Thunderbird executed JavaScript in XBL
controls. It is possible for a malicious HTML mail to leverage this
vulnerability to execute other JavaScript based attacks even when
JavaScript is disabled. (CVE-2005-2261)

A bug was found in the way Thunderbird handled certain JavaScript
functions. It is possible for a malicious HTML mail to crash the
client by executing malformed JavaScript code. (CVE-2005-2265)

A bug was found in the way Thunderbird handled child frames. It is
possible for a malicious framed HTML mail to steal sensitive
information from its parent frame. (CVE-2005-2266)

A bug was found in the way Thunderbird handled DOM node names. It is
possible for a malicious HTML mail to overwrite a DOM node name,
allowing certain privileged chrome actions to execute the malicious
JavaScript. (CVE-2005-2269)

A bug was found in the way Thunderbird cloned base objects. It is
possible for HTML content to navigate up the prototype chain to gain
access to privileged chrome objects. (CVE-2005-2270)

Users of Thunderbird are advised to upgrade to this updated package
that contains Thunderbird version 1.0.6 and is not vulnerable to these
issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-July/011947.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3fb828d6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-July/011957.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6142845f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-July/011958.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ded5bc3e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Suite/Firefox compareTo() Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/23");
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
if (rpm_check(release:"CentOS-4", reference:"thunderbird-1.0.6-1.4.1.centos4")) flag++;


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
