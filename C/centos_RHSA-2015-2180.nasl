#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2180 and 
# CentOS Errata and Security Advisory 2015:2180 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87140);
  script_version("2.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-0334");
  script_xref(name:"RHSA", value:"2015:2180");

  script_name(english:"CentOS 7 : rubygem-bundler / rubygem-thor (CESA-2015:2180)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rubygem-bundler and rubygem-thor packages that fix one
security issue, several bugs, and add various enhancements are now
available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Bundler manages an application's dependencies through its entire life,
across many machines, systematically and repeatably. Thor is a toolkit
for building powerful command-line interfaces.

A flaw was found in the way Bundler handled gems available from
multiple sources. An attacker with access to one of the sources could
create a malicious gem with the same name, which they could then use
to trick a user into installing, potentially resulting in execution of
code from the attacker-supplied malicious gem. (CVE-2013-0334)

Bundler has been upgraded to upstream version 1.7.8 and Thor has been
upgraded to upstream version 1.19.1, both of which provide a number of
bug fixes and enhancements over the previous versions. (BZ#1194243,
BZ#1209921)

All rubygem-bundler and rubygem-thor users are advised to upgrade to
these updated packages, which correct these issues and add these
enhancements."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2015-November/002604.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?472a5899"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2015-November/002605.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc429d95"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rubygem-bundler and / or rubygem-thor packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0334");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-bundler-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-thor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-thor-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rubygem-bundler-1.7.8-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rubygem-bundler-doc-1.7.8-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rubygem-thor-0.19.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rubygem-thor-doc-0.19.1-1.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rubygem-bundler / rubygem-bundler-doc / rubygem-thor / etc");
}
