#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(57211);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2011-0786", "CVE-2011-0788", "CVE-2011-0802", "CVE-2011-0814", "CVE-2011-0815", "CVE-2011-0817", "CVE-2011-0862", "CVE-2011-0863", "CVE-2011-0864", "CVE-2011-0865", "CVE-2011-0866", "CVE-2011-0867", "CVE-2011-0868", "CVE-2011-0869", "CVE-2011-0871", "CVE-2011-0872", "CVE-2011-0873");

  script_name(english:"SuSE 10 Security Update : Sun/Oracle Java (ZYPP Patch Number 7569)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Oracle Java 6 Update 26 fixes several security vulnerabilities.

Please refer to Oracle's site for further information:
http://www.oracle.com/technetwork/topics/security/javacpujune2011-3133
39.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0786.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0788.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0802.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0814.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0815.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0817.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0862.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0863.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0864.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0865.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0866.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0867.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0868.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0869.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0871.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0872.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0873.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7569.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:4, reference:"java-1_6_0-sun-1.6.0.u26-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"java-1_6_0-sun-alsa-1.6.0.u26-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"java-1_6_0-sun-demo-1.6.0.u26-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"java-1_6_0-sun-devel-1.6.0.u26-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"java-1_6_0-sun-jdbc-1.6.0.u26-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"java-1_6_0-sun-src-1.6.0.u26-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"java-1_6_0-sun-plugin-1.6.0.u26-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"java-1_6_0-sun-32bit-1.6.0.u26-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"java-1_6_0-sun-plugin-32bit-1.6.0.u26-0.11.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
