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
  script_id(61158);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2011-3389",
    "CVE-2011-3516",
    "CVE-2011-3521",
    "CVE-2011-3544",
    "CVE-2011-3545",
    "CVE-2011-3546",
    "CVE-2011-3547",
    "CVE-2011-3548",
    "CVE-2011-3549",
    "CVE-2011-3550",
    "CVE-2011-3551",
    "CVE-2011-3552",
    "CVE-2011-3553",
    "CVE-2011-3554",
    "CVE-2011-3555",
    "CVE-2011-3556",
    "CVE-2011-3557",
    "CVE-2011-3558",
    "CVE-2011-3560",
    "CVE-2011-3561"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"Scientific Linux Security Update : java-1.6.0-sun on SL5.x i386/x86_64 (BEAST)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Scientific Linux host is missing one or more security
updates.");
  script_set_attribute(attribute:"description", value:
"The Sun 1.6.0 Java release includes the Sun Java 6 Runtime Environment
and the Sun Java 6 Software Development Kit.

This update fixes several vulnerabilities in the Sun Java 6 Runtime
Environment and the Sun Java 6 Software Development Kit. Further
information about these flaws can be found on the Oracle Java SE
Critical Patch page, listed in the References section. (CVE-2011-3389,
CVE-2011-3516, CVE-2011-3521, CVE-2011-3544, CVE-2011-3545,
CVE-2011-3546, CVE-2011-3547, CVE-2011-3548, CVE-2011-3549,
CVE-2011-3550, CVE-2011-3551, CVE-2011-3552, CVE-2011-3553,
CVE-2011-3554, CVE-2011-3555, CVE-2011-3556, CVE-2011-3557,
CVE-2011-3558, CVE-2011-3560, CVE-2011-3561)

All users of java-1.6.0-sun are advised to upgrade to these updated
packages, which provide JDK and JRE 6 Update 29 and resolve these
issues. All running instances of Sun Java must be restarted for the
update to take effect.");
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1111&L=scientific-linux-errata&T=0&P=604
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7daa5835");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.6.0-sun-compat and / or jdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java RMI Server Insecure Default Configuration Java Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"java-1.6.0-sun-compat-1.6.0.29-3.sl5.jpp")) flag++;
if (rpm_check(release:"SL5", reference:"jdk-1.6.0_29-fcs")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
