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
  script_id(97038);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-9577", "CVE-2016-9578");

  script_name(english:"Scientific Linux Security Update : spice-server on SL6.x x86_64 (20170205)");
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
"Security Fix(es) :

  - A vulnerability was discovered in spice in the server's
    protocol handling. An authenticated attacker could send
    crafted messages to the spice server causing a heap
    overflow leading to a crash or possible code execution.
    (CVE-2016-9577)

  - A vulnerability was discovered in spice in the server's
    protocol handling. An attacker able to connect to the
    spice server could send crafted messages which would
    cause the process to crash. (CVE-2016-9578)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1702&L=scientific-linux-errata&F=&S=&P=1727
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?69d9df0a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected spice-server, spice-server-debuginfo and / or
spice-server-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-server-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"spice-server-0.12.4-13.el6_8.2")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"spice-server-debuginfo-0.12.4-13.el6_8.2")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"spice-server-devel-0.12.4-13.el6_8.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "spice-server / spice-server-debuginfo / spice-server-devel");
}
