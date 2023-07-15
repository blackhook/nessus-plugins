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
  script_id(51689);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-4242", "CVE-2009-4245", "CVE-2009-4247", "CVE-2009-4248", "CVE-2009-4257", "CVE-2010-0416", "CVE-2010-0417");

  script_name(english:"SuSE 10 Security Update : Realplayer and banshee (ZYPP Patch Number 7122)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The security support of Real Player 10 was discontinued a while ago by
Real Networks.

As there are known critical security problems in Real Player 10 and we
are unable to fix them nor update to Real Player 11, we are disabling
this player.

The media player of SUSE Linux Enterprise Desktop 10, Helix Banshee,
has been switched to use the Fluendo GSTreamer MP3 codec included in
this update to keep MP3 playing abilities."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4242.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4245.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4247.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4248.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4257.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0416.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0417.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7122.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/27");
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
if (rpm_check(release:"SLED10", sp:3, reference:"RealPlayer-10.0.9-2.9.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"gst-fluendo-mp3-2-108.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"helix-banshee-0.13.2-1.16.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"helix-banshee-devel-0.13.2-1.16.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"helix-banshee-engine-gst-0.13.2-1.16.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"helix-banshee-plugins-default-0.13.2-1.16.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"helix-banshee-plugins-extra-0.13.2-1.16.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
