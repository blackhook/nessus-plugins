#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0648 and 
# CentOS Errata and Security Advisory 2006:0648 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22282);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-2024", "CVE-2006-2025", "CVE-2006-2026", "CVE-2006-3459", "CVE-2006-3460", "CVE-2006-3461", "CVE-2006-3462", "CVE-2006-3463", "CVE-2006-3464", "CVE-2006-3465");
  script_bugtraq_id(19287);
  script_xref(name:"RHSA", value:"2006:0648");

  script_name(english:"CentOS 3 : kdegraphics (CESA-2006:0648)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdegraphics packages that fix several security flaws in kfax
are now available for Red Hat Enterprise Linux 2.1, and 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The kdegraphics package contains graphics applications for the K
Desktop Environment.

Tavis Ormandy of Google discovered a number of flaws in libtiff during
a security audit. The kfax application contains a copy of the libtiff
code used for parsing TIFF files and is therefore affected by these
flaws. An attacker who has the ability to trick a user into opening a
malicious TIFF file could cause kfax to crash or possibly execute
arbitrary code. (CVE-2006-3459, CVE-2006-3460, CVE-2006-3461,
CVE-2006-3462, CVE-2006-3463, CVE-2006-3464, CVE-2006-3465)

Red Hat Enterprise Linux 4 is not vulnerable to these issues as kfax
uses the shared libtiff library which has been fixed in a previous
update.

Users of kfax should upgrade to these updated packages, which contain
backported patches and are not vulnerable to this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-August/013180.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8196a8a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-August/013181.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c595bce"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013195.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?282ae501"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdegraphics packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apple iOS MobileMail LibTIFF Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdegraphics-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/30");
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
if (rpm_check(release:"CentOS-3", reference:"kdegraphics-3.1.3-3.10")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kdegraphics-devel-3.1.3-3.10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdegraphics / kdegraphics-devel");
}
