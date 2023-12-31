#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:812 and 
# CentOS Errata and Security Advisory 2005:812 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21868);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-3185");
  script_xref(name:"RHSA", value:"2005:812");

  script_name(english:"CentOS 3 / 4 : wget (CESA-2005:812)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated wget packages that fix a security issue are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

GNU Wget is a file retrieval utility that can use either the HTTP or
FTP protocols.

A stack based buffer overflow bug was found in the wget implementation
of NTLM authentication. An attacker could execute arbitrary code on a
user's machine if the user can be tricked into connecting to a
malicious web server using NTLM authentication. The Common
Vulnerabilities and Exposures project has assigned the name
CVE-2005-3185 to this issue.

All users of wget are advised to upgrade to these updated packages,
which contain a backported patch that resolves this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-November/012351.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7c5d62ee"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-November/012356.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?217fc7a3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-November/012366.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6957b0f5"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-November/012367.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e9312425"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-November/012369.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a5db740"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-November/012372.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?39bf0172"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected wget package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wget");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/02");
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
if (rpm_check(release:"CentOS-3", reference:"wget-1.10.2-0.30E")) flag++;

if (rpm_check(release:"CentOS-4", reference:"wget-1.10.2-0.40E")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wget");
}
