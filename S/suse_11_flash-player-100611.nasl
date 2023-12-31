#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(50901);
  script_version("1.35");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/08");

  script_cve_id(
    "CVE-2008-4546",
    "CVE-2009-3793",
    "CVE-2010-1297",
    "CVE-2010-2160",
    "CVE-2010-2161",
    "CVE-2010-2162",
    "CVE-2010-2163",
    "CVE-2010-2164",
    "CVE-2010-2165",
    "CVE-2010-2166",
    "CVE-2010-2167",
    "CVE-2010-2169",
    "CVE-2010-2170",
    "CVE-2010-2171",
    "CVE-2010-2172",
    "CVE-2010-2173",
    "CVE-2010-2174",
    "CVE-2010-2175",
    "CVE-2010-2176",
    "CVE-2010-2177",
    "CVE-2010-2178",
    "CVE-2010-2179",
    "CVE-2010-2180",
    "CVE-2010-2181",
    "CVE-2010-2182",
    "CVE-2010-2183",
    "CVE-2010-2184",
    "CVE-2010-2185",
    "CVE-2010-2186",
    "CVE-2010-2187",
    "CVE-2010-2188",
    "CVE-2010-2189"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"SuSE 11 / 11.1 Security Update : flash-player (SAT Patch Numbers 2539 / 2541)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SuSE 11 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update fixes multiple critical security vulnerabilities which
allow an attacker to remotely execute arbitrary code or to cause a
denial of service. The following CVE numbers have been assigned :

  - CVE-2008-4546

  - CVE-2009-3793

  - CVE-2010-1297

  - CVE-2010-2160

  - CVE-2010-2161

  - CVE-2010-2162

  - CVE-2010-2163

  - CVE-2010-2164

  - CVE-2010-2165

  - CVE-2010-2166

  - CVE-2010-2167

  - CVE-2010-2169

  - CVE-2010-2170

  - CVE-2010-2171

  - CVE-2010-2172

  - CVE-2010-2173

  - CVE-2010-2174

  - CVE-2010-2175

  - CVE-2010-2176

  - CVE-2010-2177

  - CVE-2010-2178

  - CVE-2010-2179

  - CVE-2010-2180

  - CVE-2010-2181

  - CVE-2010-2182

  - CVE-2010-2183

  - CVE-2010-2184

  - CVE-2010-2185

  - CVE-2010-2186

  - CVE-2010-2187

  - CVE-2010-2188

  - CVE-2010-2189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.novell.com/show_bug.cgi?id=612063");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2008-4546.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2009-3793.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-1297.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2160.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2161.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2162.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2163.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2164.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2165.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2166.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2167.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2169.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2170.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2171.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2172.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2173.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2174.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2175.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2176.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2177.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2178.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2179.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2180.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2181.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2182.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2183.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2184.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2185.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2186.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2187.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2188.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-2189.html");
  script_set_attribute(attribute:"solution", value:
"Apply SAT patch number 2539 / 2541 as appropriate.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player "newfunction" Invalid Pointer Use');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-164");
  script_cwe_id(399);

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:flash-player");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"flash-player-10.1.53.64-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"flash-player-10.1.53.64-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
