#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0720 and 
# CentOS Errata and Security Advisory 2006:0720 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22880);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-4811");
  script_bugtraq_id(20599);
  script_xref(name:"RHSA", value:"2006:0720");

  script_name(english:"CentOS 3 / 4 : kdelibs (CESA-2006:0720)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdelibs packages that correct an integer overflow flaw are now
available.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

The kdelibs package provides libraries for the K Desktop Environment
(KDE). Qt is a GUI software toolkit for the X Window System.

An integer overflow flaw was found in the way Qt handled pixmap
images. The KDE khtml library uses Qt in such a way that untrusted
parameters could be passed to Qt, triggering the overflow. An attacker
could for example create a malicious web page that when viewed by a
victim in the Konqueror browser would cause Konqueror to crash or
possibly execute arbitrary code with the privileges of the victim.
(CVE-2006-4811)

Users of KDE should upgrade to these updated packages, which contain a
backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-October/013325.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?31b7878d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-October/013326.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ea9a0277"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-October/013330.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?14b72e32"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-October/013331.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b4294cec"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-October/013336.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f99452e6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-October/013337.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98ebceac"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdelibs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/20");
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
if (rpm_check(release:"CentOS-3", reference:"kdelibs-3.1.3-6.12")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kdelibs-devel-3.1.3-6.12")) flag++;

if (rpm_check(release:"CentOS-4", reference:"kdelibs-3.3.1-6.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kdelibs-devel-3.3.1-6.RHEL4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdelibs / kdelibs-devel");
}
