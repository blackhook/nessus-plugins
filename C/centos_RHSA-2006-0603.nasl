#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0603 and 
# CentOS Errata and Security Advisory 2006:0603 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22161);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-2656", "CVE-2006-3459", "CVE-2006-3460", "CVE-2006-3461", "CVE-2006-3462", "CVE-2006-3463", "CVE-2006-3464", "CVE-2006-3465");
  script_bugtraq_id(19287);
  script_xref(name:"RHSA", value:"2006:0603");

  script_name(english:"CentOS 3 / 4 : libtiff (CESA-2006:0603)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libtiff packages that fix several security flaws are now
available for Red Hat Enterprise Linux.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The libtiff package contains a library of functions for manipulating
TIFF (Tagged Image File Format) files.

Tavis Ormandy of Google discovered a number of flaws in libtiff during
a security audit. An attacker could create a carefully crafted TIFF
file in such a way that it was possible to cause an application linked
with libtiff to crash or possibly execute arbitrary code.
(CVE-2006-3459, CVE-2006-3460, CVE-2006-3461, CVE-2006-3462,
CVE-2006-3463, CVE-2006-3464, CVE-2006-3465)

All users are advised to upgrade to these updated packages, which
contain backported fixes for these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-August/013105.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?15313995"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-August/013110.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e39be2fb"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-August/013120.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ac745cf6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-August/013121.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f193bb64"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtiff packages."
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/07");
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
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"libtiff-3.5.7-25.el3.4")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"libtiff-devel-3.5.7-25.el3.4")) flag++;

if (rpm_check(release:"CentOS-4", reference:"libtiff-3.6.1-12")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libtiff-devel-3.6.1-12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff / libtiff-devel");
}
