#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81294);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-3675", "CVE-2014-3676", "CVE-2014-3677");

  script_name(english:"Scientific Linux Security Update : shim on SL7.x x86_64 (20141104)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A heap-based buffer overflow flaw was found the way shim parsed
certain IPv6 addresses. If IPv6 network booting was enabled, a
malicious server could supply a crafted IPv6 address that would cause
shim to crash or, potentially, execute arbitrary code. (CVE-2014-3676)

An out-of-bounds memory write flaw was found in the way shim processed
certain Machine Owner Keys (MOKs). A local attacker could potentially
use this flaw to execute arbitrary code on the system. (CVE-2014-3677)

An out-of-bounds memory read flaw was found in the way shim parsed
certain IPv6 packets. A specially crafted DHCPv6 packet could possibly
cause shim to crash, preventing the system from booting if IPv6
booting was enabled. (CVE-2014-3675)

The system must be rebooted for this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1502&L=scientific-linux-errata&T=0&P=540
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c228da8a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mokutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:shim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:shim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:shim-unsigned");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mokutil-0.7-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"shim-0.7-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"shim-debuginfo-0.7-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"shim-unsigned-0.7-8.el7_0")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mokutil / shim / shim-debuginfo / shim-unsigned");
}
