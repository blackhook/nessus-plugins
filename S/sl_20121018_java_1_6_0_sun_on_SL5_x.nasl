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
  script_id(62773);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-0547", "CVE-2012-1531", "CVE-2012-1532", "CVE-2012-1533", "CVE-2012-3143", "CVE-2012-3159", "CVE-2012-3216", "CVE-2012-4416", "CVE-2012-5068", "CVE-2012-5069", "CVE-2012-5071", "CVE-2012-5072", "CVE-2012-5073", "CVE-2012-5075", "CVE-2012-5077", "CVE-2012-5079", "CVE-2012-5081", "CVE-2012-5083", "CVE-2012-5084", "CVE-2012-5085", "CVE-2012-5086", "CVE-2012-5089");

  script_name(english:"Scientific Linux Security Update : java-1.6.0-sun on SL5.x i386/x86_64 (20121018) (ROBOT)");
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
"As a reminder, the openjdk Java environment is available in Scientific
Linux 5. Updates for openjdk are released in a similar manner to other
security updates. Scientific Linux 6 does not bundle the closed source
Java environment.

All running instances of Sun/Oracle Java must be restarted for the
update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1210&L=scientific-linux-errata&T=0&P=3435
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a783361"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-sun-compat and / or jdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Web Start Double Quote Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.6.0-sun-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:jdk");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/31");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 5.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"java-1.6.0-sun-compat-1.6.0.37-3.sl5.jpp")) flag++;
if (rpm_check(release:"SL5", reference:"jdk-1.6.0_37-fcs")) flag++;


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
