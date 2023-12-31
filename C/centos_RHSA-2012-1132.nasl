#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1132 and 
# CentOS Errata and Security Advisory 2012:1132 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67094);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-3422", "CVE-2012-3423");
  script_xref(name:"RHSA", value:"2012:1132");

  script_name(english:"CentOS 6 : icedtea-web (CESA-2012:1132)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated icedtea-web packages that fix two security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The IcedTea-Web project provides a Java web browser plug-in and an
implementation of Java Web Start, which is based on the Netx project.
It also contains a configuration tool for managing deployment settings
for the plug-in and Web Start implementations.

An uninitialized pointer use flaw was found in the IcedTea-Web
plug-in. Visiting a malicious web page could possibly cause a web
browser using the IcedTea-Web plug-in to crash, disclose a portion of
its memory, or execute arbitrary code. (CVE-2012-3422)

It was discovered that the IcedTea-Web plug-in incorrectly assumed all
strings received from the browser were NUL terminated. When using the
plug-in with a web browser that does not NUL terminate strings,
visiting a web page containing a Java applet could possibly cause the
browser to crash, disclose a portion of its memory, or execute
arbitrary code. (CVE-2012-3423)

Red Hat would like to thank Chamal De Silva for reporting the
CVE-2012-3422 issue.

This erratum also upgrades IcedTea-Web to version 1.2.1. Refer to the
NEWS file, linked to in the References, for further information.

All IcedTea-Web users should upgrade to these updated packages, which
resolve these issues. Web browsers using the IcedTea-Web browser
plug-in must be restarted for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-July/018778.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e5105b43"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected icedtea-web packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-3423");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:icedtea-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:icedtea-web-javadoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/29");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"icedtea-web-1.2.1-1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"icedtea-web-javadoc-1.2.1-1.el6_3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icedtea-web / icedtea-web-javadoc");
}
