#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0500 and 
# CentOS Errata and Security Advisory 2013:0500 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65136);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-2722", "CVE-2013-0200");
  script_bugtraq_id(48892, 58079);
  script_xref(name:"RHSA", value:"2013:0500");

  script_name(english:"CentOS 6 : hplip (CESA-2013:0500)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated hplip packages that fix several security issues, multiple
bugs, and add various enhancements are now available for Red Hat
Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The hplip packages contain the Hewlett-Packard Linux Imaging and
Printing Project (HPLIP), which provides drivers for Hewlett-Packard
printers and multi-function peripherals.

Several temporary file handling flaws were found in HPLIP. A local
attacker could use these flaws to perform a symbolic link attack,
overwriting arbitrary files accessible to a process using HPLIP.
(CVE-2013-0200, CVE-2011-2722)

The CVE-2013-0200 issues were discovered by Tim Waugh of Red Hat.

The hplip packages have been upgraded to upstream version 3.12.4,
which provides a number of bug fixes and enhancements over the
previous version. (BZ#731900)

This update also fixes the following bugs :

* Previously, the hpijs package required the obsolete cupsddk-drivers
package, which was provided by the cups package. Under certain
circumstances, this dependency caused hpijs installation to fail. This
bug has been fixed and hpijs no longer requires cupsddk-drivers.
(BZ#829453)

* The configuration of the Scanner Access Now Easy (SANE) back end is
located in the /etc/sane.d/dll.d/ directory, however, the hp-check
utility checked only the /etc/sane.d/dll.conf file. Consequently,
hp-check checked for correct installation, but incorrectly reported a
problem with the way the SANE back end was installed. With this
update, hp-check properly checks for installation problems in both
locations as expected. (BZ#683007)

All users of hplip are advised to upgrade to these updated packages,
which fix these issues and add these enhancements."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019339.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?339dc434"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-February/000528.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?658cf9cf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected hplip packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0200");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hpijs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hplip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hplip-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hplip-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hplip-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsane-hpaio");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/10");
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
if (rpm_check(release:"CentOS-6", reference:"hpijs-3.12.4-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"hplip-3.12.4-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"hplip-common-3.12.4-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"hplip-gui-3.12.4-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"hplip-libs-3.12.4-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsane-hpaio-3.12.4-4.el6")) flag++;


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
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hpijs / hplip / hplip-common / hplip-gui / hplip-libs / etc");
}
