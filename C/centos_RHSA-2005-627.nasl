#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:627 and 
# CentOS Errata and Security Advisory 2005:627 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21846);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-2102", "CVE-2005-2103", "CVE-2005-2370");
  script_bugtraq_id(14531);
  script_xref(name:"RHSA", value:"2005:627");

  script_name(english:"CentOS 3 / 4 : gaim (CESA-2005:627)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated gaim package that fixes multiple security issues is now
available.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Gaim is an Internet Messaging client.

A heap based buffer overflow issue was discovered in the way Gaim
processes away messages. A remote attacker could send a specially
crafted away message to a Gaim user logged into AIM or ICQ that could
result in arbitrary code execution. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2005-2103
to this issue.

Daniel Atallah discovered a denial of service issue in Gaim. A remote
attacker could attempt to upload a file with a specially crafted name
to a user logged into AIM or ICQ, causing Gaim to crash. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-2102 to this issue.

A denial of service bug was found in Gaim's Gadu Gadu protocol
handler. A remote attacker could send a specially crafted message to a
Gaim user logged into Gadu Gadu, causing Gaim to crash. Please note
that this issue only affects PPC and IBM S/390 systems running Gaim.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-2370 to this issue.

Users of gaim are advised to upgrade to this updated package, which
contains backported patches and is not vulnerable to these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-August/012035.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bde62fab"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-August/012036.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4e9f139"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-August/012047.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2fd32204"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-August/012048.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c1479ab"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-August/012049.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e4ca783"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-August/012050.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?72e67002"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gaim package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gaim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/10");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"gaim-1.3.1-0.el3.3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"gaim-1.3.1-0.el4.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gaim");
}
