#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:650 and 
# CentOS Errata and Security Advisory 2004:650 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21794);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2004-0110", "CVE-2004-0989");
  script_bugtraq_id(9718);
  script_xref(name:"RHSA", value:"2004:650");

  script_name(english:"CentOS 3 : libxml (CESA-2004:650)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated libxml package that fixes multiple buffer overflows is now
available.

[Updated 24 May 2005] Multilib packages have been added to this
advisory

The libxml package contains a library for manipulating XML files.

Multiple buffer overflow bugs have been found in libxml versions prior
to 2.6.14. If an attacker can trick a user into passing a specially
crafted FTP URL or FTP proxy URL to an application that uses the
vulnerable functions of libxml, it could be possible to execute
arbitrary code. Additionally, if an attacker can return a specially
crafted DNS request to libxml, it could be possible to execute
arbitrary code. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-0989 to this issue.

Yuuichi Teranishi discovered a flaw in libxml versions prior to 2.6.6.
When fetching a remote resource via FTP or HTTP, libxml uses special
parsing routines. These routines can overflow a buffer if passed a
very long URL. If an attacker is able to find an application using
libxml that parses remote resources and allows them to influence the
URL, then this flaw could be used to execute arbitrary code. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-0110 to this issue.

All users are advised to upgrade to this updated package, which
contains backported patches and is not vulnerable to these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011765.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?784e2f8f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011766.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fed3aced"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/27");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libxml-1.8.17-9.2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libxml-1.8.17-9.2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libxml-devel-1.8.17-9.2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libxml-devel-1.8.17-9.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml / libxml-devel");
}
