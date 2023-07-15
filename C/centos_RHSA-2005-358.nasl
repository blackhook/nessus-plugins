#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:358 and 
# CentOS Errata and Security Advisory 2005:358 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21927);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-2491");
  script_bugtraq_id(14620);
  script_xref(name:"RHSA", value:"2005:358");

  script_name(english:"CentOS 4 : exim (CESA-2005:358)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated exim packages that fix a security issue in PCRE and a free
space computation on large file system bug are now available for Red
Hat Enterprise Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Exim is a mail transport agent (MTA) developed at the University of
Cambridge for use on Unix systems connected to the Internet.

An integer overflow flaw was found in PCRE, a Perl-compatible regular
expression library included within Exim. A local user could create a
maliciously crafted regular expression in such as way that they could
gain the privileges of the 'exim' user. The Common Vulnerabilities and
Exposures project assigned the name CVE-2005-2491 to this issue. These
erratum packages change Exim to use the system PCRE library instead of
the internal one.

These packages also fix a minor flaw where the Exim Monitor was
incorrectly computing free space on very large file systems.

Users should upgrade to these erratum packages and also ensure they
have updated the system PCRE library, for which erratum packages are
available separately in RHSA-2005:761"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012135.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12f22fc3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012137.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb4e6268"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012138.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?21c6b819"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected exim packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:exim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:exim-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:exim-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:exim-sa");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/08");
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
if (rpm_check(release:"CentOS-4", reference:"exim-4.43-1.RHEL4.5")) flag++;
if (rpm_check(release:"CentOS-4", reference:"exim-doc-4.43-1.RHEL4.5")) flag++;
if (rpm_check(release:"CentOS-4", reference:"exim-mon-4.43-1.RHEL4.5")) flag++;
if (rpm_check(release:"CentOS-4", reference:"exim-sa-4.43-1.RHEL4.5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exim / exim-doc / exim-mon / exim-sa");
}
