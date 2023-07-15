#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0811 and 
# CentOS Errata and Security Advisory 2012:0811 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59922);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-3294");
  script_bugtraq_id(43218);
  script_xref(name:"RHSA", value:"2012:0811");

  script_name(english:"CentOS 6 : php-pecl-apc (CESA-2012:0811)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php-pecl-apc packages that fix one security issue, several
bugs, and add various enhancements are now available for Red Hat
Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The php-pecl-apc packages contain APC (Alternative PHP Cache), the
framework for caching and optimization of intermediate PHP code.

A cross-site scripting (XSS) flaw was found in the 'apc.php' script,
which provides a detailed analysis of the internal workings of APC and
is shipped as part of the APC extension documentation. A remote
attacker could possibly use this flaw to conduct a cross-site
scripting attack. (CVE-2010-3294)

Note: The administrative script is not deployed upon package
installation. It must manually be copied to the web root (the default
is '/var/www/html/', for example).

In addition, the php-pecl-apc packages have been upgraded to upstream
version 3.1.9, which provides a number of bug fixes and enhancements
over the previous version. (BZ#662655)

All users of php-pecl-apc are advised to upgrade to these updated
packages, which fix these issues and add these enhancements. If the
'apc.php' script was previously deployed in the web root, it must
manually be re-deployed to replace the vulnerable version to resolve
this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-July/018713.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?899c2147"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-pecl-apc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-3294");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pecl-apc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pecl-apc-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"php-pecl-apc-3.1.9-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pecl-apc-devel-3.1.9-2.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-pecl-apc / php-pecl-apc-devel");
}
