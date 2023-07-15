#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:1546 and 
# Oracle Linux Security Advisory ELSA-2016-1546 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(92689);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-8127", "CVE-2014-8129", "CVE-2014-8130", "CVE-2014-9330", "CVE-2014-9655", "CVE-2015-1547", "CVE-2015-7554", "CVE-2015-8665", "CVE-2015-8668", "CVE-2015-8683", "CVE-2015-8781", "CVE-2015-8782", "CVE-2015-8783", "CVE-2015-8784", "CVE-2016-3632", "CVE-2016-3945", "CVE-2016-3990", "CVE-2016-3991", "CVE-2016-5320");
  script_xref(name:"RHSA", value:"2016:1546");

  script_name(english:"Oracle Linux 7 : libtiff (ELSA-2016-1546)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:1546 :

An update for libtiff is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The libtiff packages contain a library of functions for manipulating
Tagged Image File Format (TIFF) files.

Security Fix(es) :

* Multiple flaws have been discovered in libtiff. A remote attacker
could exploit these flaws to cause a crash or memory corruption and,
possibly, execute arbitrary code by tricking an application linked
against libtiff into processing specially crafted files.
(CVE-2014-9655, CVE-2015-1547, CVE-2015-8784, CVE-2015-8683,
CVE-2015-8665, CVE-2015-8781, CVE-2015-8782, CVE-2015-8783,
CVE-2016-3990, CVE-2016-5320)

* Multiple flaws have been discovered in various libtiff tools
(bmp2tiff, pal2rgb, thumbnail, tiff2bw, tiff2pdf, tiffcrop,
tiffdither, tiffsplit, tiff2rgba). By tricking a user into processing
a specially crafted file, a remote attacker could exploit these flaws
to cause a crash or memory corruption and, possibly, execute arbitrary
code with the privileges of the user running the libtiff tool.
(CVE-2014-8127, CVE-2014-8129, CVE-2014-8130, CVE-2014-9330,
CVE-2015-7554, CVE-2015-8668, CVE-2016-3632, CVE-2016-3945,
CVE-2016-3991)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-August/006236.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtiff packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtiff-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtiff-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libtiff-4.0.3-25.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libtiff-devel-4.0.3-25.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libtiff-static-4.0.3-25.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libtiff-tools-4.0.3-25.el7_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff / libtiff-devel / libtiff-static / libtiff-tools");
}
