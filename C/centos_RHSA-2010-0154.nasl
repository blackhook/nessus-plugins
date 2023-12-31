#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0154 and 
# CentOS Errata and Security Advisory 2010:0154 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(45093);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-0689", "CVE-2009-1571", "CVE-2009-2462", "CVE-2009-2463", "CVE-2009-2466", "CVE-2009-2470", "CVE-2009-3072", "CVE-2009-3075", "CVE-2009-3076", "CVE-2009-3077", "CVE-2009-3274", "CVE-2009-3376", "CVE-2009-3380", "CVE-2009-3384", "CVE-2009-3979", "CVE-2010-0159", "CVE-2010-0163", "CVE-2010-0169", "CVE-2010-0171");
  script_bugtraq_id(35765, 35769, 35776, 36343, 36851, 36852, 36867, 36871, 37361, 38286, 38287);
  script_xref(name:"RHSA", value:"2010:0154");

  script_name(english:"CentOS 4 : thunderbird (CESA-2010:0154)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated thunderbird package that fixes several security issues is
now available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the processing of malformed HTML mail
content. An HTML mail message containing malicious content could cause
Thunderbird to crash or, potentially, execute arbitrary code with the
privileges of the user running Thunderbird. (CVE-2009-2462,
CVE-2009-2463, CVE-2009-2466, CVE-2009-3072, CVE-2009-3075,
CVE-2009-3380, CVE-2009-3979, CVE-2010-0159)

A use-after-free flaw was found in Thunderbird. An attacker could use
this flaw to crash Thunderbird or, potentially, execute arbitrary code
with the privileges of the user running Thunderbird. (CVE-2009-3077)

A heap-based buffer overflow flaw was found in the Thunderbird string
to floating point conversion routines. An HTML mail message containing
malicious JavaScript could crash Thunderbird or, potentially, execute
arbitrary code with the privileges of the user running Thunderbird.
(CVE-2009-0689)

A use-after-free flaw was found in Thunderbird. Under low memory
conditions, viewing an HTML mail message containing malicious content
could result in Thunderbird executing arbitrary code with the
privileges of the user running Thunderbird. (CVE-2009-1571)

A flaw was found in the way Thunderbird created temporary file names
for downloaded files. If a local attacker knows the name of a file
Thunderbird is going to download, they can replace the contents of
that file with arbitrary contents. (CVE-2009-3274)

A flaw was found in the way Thunderbird displayed a right-to-left
override character when downloading a file. In these cases, the name
displayed in the title bar differed from the name displayed in the
dialog body. An attacker could use this flaw to trick a user into
downloading a file that has a file name or extension that is different
from what the user expected. (CVE-2009-3376)

A flaw was found in the way Thunderbird processed SOCKS5 proxy
replies. A malicious SOCKS5 server could send a specially crafted
reply that would cause Thunderbird to crash. (CVE-2009-2470)

Descriptions in the dialogs when adding and removing PKCS #11 modules
were not informative. An attacker able to trick a user into installing
a malicious PKCS #11 module could use this flaw to install their own
Certificate Authority certificates on a user's machine, making it
possible to trick the user into believing they are viewing trusted
content or, potentially, execute arbitrary code with the privileges of
the user running Thunderbird. (CVE-2009-3076)

All Thunderbird users should upgrade to this updated package, which
resolves these issues. All running instances of Thunderbird must be
restarted for the update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-March/016576.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c286a42"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-March/016577.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c84e0af0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 20, 94, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"thunderbird-1.5.0.12-25.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"thunderbird-1.5.0.12-25.el4.centos")) flag++;


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
