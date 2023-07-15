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
  script_id(61330);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/08");

  script_cve_id(
    "CVE-2012-0551",
    "CVE-2012-1711",
    "CVE-2012-1713",
    "CVE-2012-1716",
    "CVE-2012-1717",
    "CVE-2012-1718",
    "CVE-2012-1719",
    "CVE-2012-1721",
    "CVE-2012-1722",
    "CVE-2012-1723",
    "CVE-2012-1724",
    "CVE-2012-1725"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Scientific Linux Security Update : java-1.6.0-sun on SL5.x i386/x86_64 (20120613)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Scientific Linux host is missing one or more security
updates.");
  script_set_attribute(attribute:"description", value:
"The Sun 1.6.0 Java release includes the Sun Java 6 Runtime Environment
and the Sun Java 6 Software Development Kit.

This update fixes several vulnerabilities in the Sun Java 6 Runtime
Environment and the Sun Java 6 Software Development Kit. Further
information about these flaws can be found on the Oracle Java SE
Critical Patch page, listed in the References section. (CVE-2012-0551,
CVE-2012-1711, CVE-2012-1713, CVE-2012-1716, CVE-2012-1717,
CVE-2012-1718, CVE-2012-1719, CVE-2012-1721, CVE-2012-1722,
CVE-2012-1723, CVE-2012-1724, CVE-2012-1725)

All users of java-1.6.0-sun are advised to upgrade to these updated
packages, which provide JDK and JRE 6 Update 33 and resolve these
issues. All running instances of Sun Java must be restarted for the
update to take effect.");
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1207&L=scientific-linux-errata&T=0&P=75
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1198678");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.6.0-sun-compat and / or jdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Field Bytecode Verifier Cache Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.6.0-sun-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:jdk");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Scientific Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 5.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"java-1.6.0-sun-compat-1.6.0.33-3.sl5.jpp")) flag++;
if (rpm_check(release:"SL5", reference:"jdk-1.6.0_33-fcs")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-sun-compat / jdk");
}
