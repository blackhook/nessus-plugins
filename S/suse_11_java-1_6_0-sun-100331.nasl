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
  script_id(50917);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2009-3555",
    "CVE-2010-0082",
    "CVE-2010-0084",
    "CVE-2010-0085",
    "CVE-2010-0087",
    "CVE-2010-0088",
    "CVE-2010-0089",
    "CVE-2010-0090",
    "CVE-2010-0091",
    "CVE-2010-0092",
    "CVE-2010-0093",
    "CVE-2010-0094",
    "CVE-2010-0095",
    "CVE-2010-0837",
    "CVE-2010-0838",
    "CVE-2010-0839",
    "CVE-2010-0840",
    "CVE-2010-0841",
    "CVE-2010-0842",
    "CVE-2010-0843",
    "CVE-2010-0844",
    "CVE-2010-0845",
    "CVE-2010-0846",
    "CVE-2010-0847",
    "CVE-2010-0848",
    "CVE-2010-0849",
    "CVE-2010-0850"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"SuSE 11 Security Update : Sun Java 6 (SAT Patch Number 2225)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SuSE 11 host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Sun Java 6 was updated to Update 19, fixing a large number of security
issues: CVE-2009-3555 / CVE-2010-0082 / CVE-2010-0084 / CVE-2010-0085
/ CVE-2010-0087 / CVE-2010-0088 / CVE-2010-0089 / CVE-2010-0090 /
CVE-2010-0091 / CVE-2010-0092 / CVE-2010-0093 / CVE-2010-0094 /
CVE-2010-0095 / CVE-2010-0837 / CVE-2010-0838 / CVE-2010-0839 /
CVE-2010-0840 / CVE-2010-0841 / CVE-2010-0842 / CVE-2010-0843 /
CVE-2010-0844 / CVE-2010-0845 / CVE-2010-0846 / CVE-2010-0847 /
CVE-2010-0848 / CVE-2010-0849 / CVE-2010-0850.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.novell.com/show_bug.cgi?id=578877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.novell.com/show_bug.cgi?id=592589");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2009-3555.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0082.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0084.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0085.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0087.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0088.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0089.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0090.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0091.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0092.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0093.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0094.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0095.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0837.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0838.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0839.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0840.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0841.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0842.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0843.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0844.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0845.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0846.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0847.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0848.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0849.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0850.html");
  script_set_attribute(attribute:"solution", value:
"Apply SAT patch number 2225.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java MixerSequencer Object GM_Song Structure Handling Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_cwe_id(310);

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-sun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-sun-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-sun-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-sun-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-sun-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-sun-src");
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

pl = get_kb_item("Host/SuSE/patchlevel");
if (pl) audit(AUDIT_OS_NOT, "SuSE 11.0");


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"java-1_6_0-sun-1.6.0.u19-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"java-1_6_0-sun-alsa-1.6.0.u19-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"java-1_6_0-sun-demo-1.6.0.u19-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"java-1_6_0-sun-jdbc-1.6.0.u19-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"java-1_6_0-sun-plugin-1.6.0.u19-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"java-1_6_0-sun-src-1.6.0.u19-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"java-1_6_0-sun-1.6.0.u19-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"java-1_6_0-sun-alsa-1.6.0.u19-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"java-1_6_0-sun-demo-1.6.0.u19-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"java-1_6_0-sun-jdbc-1.6.0.u19-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"java-1_6_0-sun-plugin-1.6.0.u19-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"java-1_6_0-sun-src-1.6.0.u19-0.1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
