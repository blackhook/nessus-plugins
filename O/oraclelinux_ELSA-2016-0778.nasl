#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:0778 and 
# Oracle Linux Security Advisory ELSA-2016-0778 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91150);
  script_version("2.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-5234", "CVE-2015-5235");
  script_xref(name:"RHSA", value:"2016:0778");

  script_name(english:"Oracle Linux 6 : icedtea-web (ELSA-2016-0778)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:0778 :

An update for icedtea-web is now available for Red Hat Enterprise
Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The IcedTea-Web project provides a Java web browser plug-in and an
implementation of Java Web Start, which is based on the Netx project.
It also contains a configuration tool for managing deployment settings
for the plug-in and Web Start implementations. IcedTea-Web now also
contains PolicyEditor - a simple tool to configure Java policies.

The following packages have been upgraded to a newer upstream version:
icedtea-web (1.6.2). (BZ#1275523)

Security Fix(es) :

* It was discovered that IcedTea-Web did not properly sanitize applet
URLs when storing applet trust settings. A malicious web page could
use this flaw to inject trust-settings configuration, and cause
applets to be executed without user approval. (CVE-2015-5234)

* It was discovered that IcedTea-Web did not properly determine an
applet's origin when asking the user if the applet should be run. A
malicious page could use this flaw to cause IcedTea-Web to execute the
applet without user approval, or confuse the user into approving
applet execution based on an incorrectly indicated applet origin.
(CVE-2015-5235)

Red Hat would like to thank Andrea Palazzo (Truel IT) for reporting
these issues.

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 6.8 Release Notes and Red Hat Enterprise Linux 6.8
Technical Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-May/006058.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected icedtea-web packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:icedtea-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:icedtea-web-javadoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"icedtea-web-1.6.2-1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"icedtea-web-javadoc-1.6.2-1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icedtea-web / icedtea-web-javadoc");
}
