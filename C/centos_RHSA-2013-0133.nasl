#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0133 and 
# CentOS Errata and Security Advisory 2013:0133 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63578);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-2722");
  script_bugtraq_id(48892);
  script_xref(name:"RHSA", value:"2013:0133");

  script_name(english:"CentOS 5 : hplip3 (CESA-2013:0133)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated hplip3 packages that fix one security issue and one bug are
now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Hewlett-Packard Linux Imaging and Printing (HPLIP) provides drivers
for Hewlett-Packard (HP) printers and multifunction peripherals.

It was found that the HP CUPS (Common UNIX Printing System) fax filter
in HPLIP created a temporary file in an insecure way. A local attacker
could use this flaw to perform a symbolic link attack, overwriting
arbitrary files accessible to a process using the fax filter (such as
the hp3-sendfax tool). (CVE-2011-2722)

This update also fixes the following bug :

* Previous modifications of the hplip3 package to allow it to be
installed alongside the original hplip package introduced several
problems to fax support; for example, the hp-sendfax utility could
become unresponsive. These problems have been fixed with this update.
(BZ#501834)

All users of hplip3 are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-January/019115.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8464808a"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-January/000350.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?25960a8f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected hplip3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-2722");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hpijs3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hplip3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hplip3-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hplip3-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hplip3-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsane-hpaio3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/17");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"hpijs3-3.9.8-15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"hplip3-3.9.8-15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"hplip3-common-3.9.8-15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"hplip3-gui-3.9.8-15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"hplip3-libs-3.9.8-15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libsane-hpaio3-3.9.8-15.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hpijs3 / hplip3 / hplip3-common / hplip3-gui / hplip3-libs / etc");
}
