#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0160 and 
# CentOS Errata and Security Advisory 2006:0160 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21885);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3193", "CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627", "CVE-2005-3628");
  script_bugtraq_id(15721, 15725, 15726, 15727, 16143);
  script_xref(name:"RHSA", value:"2006:0160");

  script_name(english:"CentOS 3 / 4 : tetex (CESA-2006:0160)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tetex packages that fix several integer overflows are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

TeTeX is an implementation of TeX. TeX takes a text file and a set of
formatting commands as input and creates a typesetter-independent .dvi
(DeVice Independent) file as output.

Several flaws were discovered in the teTeX PDF parsing library. An
attacker could construct a carefully crafted PDF file that could cause
teTeX to crash or possibly execute arbitrary code when opened. The
Common Vulnerabilities and Exposures project assigned the names
CVE-2005-3191, CVE-2005-3192, CVE-2005-3193, CVE-2005-3624,
CVE-2005-3625, CVE-2005-3626, CVE-2005-3627 and CVE-2005-3628 to these
issues.

Users of teTeX should upgrade to these updated packages, which contain
backported patches and are not vulnerable to these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-January/012585.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c77f4c95"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-January/012586.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?718b5d7d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-January/012591.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6516374d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-January/012592.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?10d48e68"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-January/012594.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b95bc89"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-January/012595.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4eadcf29"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tetex packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex-afm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex-xdvi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/19");
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
if (rpm_check(release:"CentOS-3", reference:"tetex-1.0.7-67.9")) flag++;
if (rpm_check(release:"CentOS-3", reference:"tetex-afm-1.0.7-67.9")) flag++;
if (rpm_check(release:"CentOS-3", reference:"tetex-doc-1.0.7-67.9")) flag++;
if (rpm_check(release:"CentOS-3", reference:"tetex-dvips-1.0.7-67.9")) flag++;
if (rpm_check(release:"CentOS-3", reference:"tetex-fonts-1.0.7-67.9")) flag++;
if (rpm_check(release:"CentOS-3", reference:"tetex-latex-1.0.7-67.9")) flag++;
if (rpm_check(release:"CentOS-3", reference:"tetex-xdvi-1.0.7-67.9")) flag++;

if (rpm_check(release:"CentOS-4", reference:"tetex-2.0.2-22.EL4.7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"tetex-afm-2.0.2-22.EL4.7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"tetex-doc-2.0.2-22.EL4.7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"tetex-dvips-2.0.2-22.EL4.7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"tetex-fonts-2.0.2-22.EL4.7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"tetex-latex-2.0.2-22.EL4.7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"tetex-xdvi-2.0.2-22.EL4.7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tetex / tetex-afm / tetex-doc / tetex-dvips / tetex-fonts / etc");
}
