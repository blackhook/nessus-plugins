#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0126 and 
# CentOS Errata and Security Advisory 2013:0126 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63571);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-2124");
  script_bugtraq_id(57201);
  script_xref(name:"RHSA", value:"2013:0126");

  script_name(english:"CentOS 5 : squirrelmail (CESA-2013:0126)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated squirrelmail package that fixes one security issue and
several bugs is now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

SquirrelMail is a standards-based webmail package written in PHP.

The SquirrelMail security update RHSA-2012:0103 did not, unlike the
erratum text stated, correct the CVE-2010-2813 issue, a flaw in the
way SquirrelMail handled failed log in attempts. A user preference
file was created when attempting to log in with a password containing
an 8-bit character, even if the username was not valid. A remote
attacker could use this flaw to eventually consume all hard disk space
on the target SquirrelMail server. (CVE-2012-2124)

This update also fixes the following bugs :

* Prior to this update, SquirrelMail could not decode multi-line
subjects properly. Consequently, the decode header
internationalization option did not properly handle new lines or tabs
at the beginning of the lines. This bug has been fixed and
SquirrelMail now works correctly in the described scenario.
(BZ#241861)

* Due to a bug, attachments written in HTML code on the Windows
operating system were not displayed properly when accessed with
SquirrelMail; the '!=null' string was trimmed to '!ull'. This bug has
been fixed and the attachments are now displayed correctly in such a
case. (BZ#359791)

* Previously, e-mail messages with a Unique Identifier (UID) larger
than 2^31 bytes were unreadable when using the squirrelmail package.
With this patch the squirrelmail package is able to read all messages
regardless of the UIDs size. (BZ#450780)

* Due to a bug, a PHP script did not assign the proper character set
to requested variables. Consequently, SquirrelMail could not display
any e-mails. The underlying source code has been modified and now the
squirrelmail package assigns the correct character set. (BZ#475188)

* Due to the incorrect internationalization option located at the
i18n.php file, the squirrelmail package could not use the GB 2312
character set. The i18n.php file has been fixed and the GB 2312
character set works correctly in the described scenario. (BZ#508686)

* Previously, the preg_split() function contained a misspelled
constant, PREG_SPLIT_NI_EMPTY, which could cause SquirrelMail to
produce error messages. The name of the constant has been corrected to
PREG_SPLIT_NO_EMPTY, and SquirrelMail no longer produces error
messages in this scenario. (BZ#528758)

* Due to Security-Enhanced Linux (SELinux) settings, sending e-mails
from the SquirrelMail web interface was blocked. This update adds a
note to the SquirrelMail documentation that describes how to set the
SELinux options to allow sending e-mails from the SquirrelMail web
interface. (BZ#745380)

* Previously, the squirrelmail package did not comply with the RFC
2822 specification about line length limits. Consequently, attachments
with lines longer than 998 characters could not be forwarded using
SquirrelMail. This patch modifies the underlying source code and now
SquirrelMail complies with the RFC 2822 specification as expected.
(BZ#745469)

* Prior to this update, the squirrelmail package required the
php-common script instead of the mod_php script during installation or
upgrade of the package, which led to a dependency error. As a result,
attempting to install or upgrade the squirrelmail package failed on
systems using the php53 packages. With this update, the dependencies
of the squirrelmail package were changed and the installation or
upgrade now works correctly in the described scenario. (BZ#789353)

All users of SquirrelMail are advised to upgrade to this updated
package, which contains backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-January/019177.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd3d003b"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-January/000439.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f35d3e7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squirrelmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-2124");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squirrelmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", reference:"squirrelmail-1.4.8-21.el5.centos")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squirrelmail");
}
