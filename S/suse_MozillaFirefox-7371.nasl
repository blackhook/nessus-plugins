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
  script_id(52736);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2010-1585", "CVE-2011-0051", "CVE-2011-0053", "CVE-2011-0054", "CVE-2011-0055", "CVE-2011-0056", "CVE-2011-0057", "CVE-2011-0058", "CVE-2011-0059", "CVE-2011-0061", "CVE-2011-0062");

  script_name(english:"SuSE 10 Security Update : Mozilla Firefox (ZYPP Patch Number 7371)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox has been updated to version 3.6.15, fixing the
following"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-01.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-01/"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-02.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-02/"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-03.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-03/"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-05.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-05/"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-06.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-06/"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-07.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-07/"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-08.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-08/"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-09.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-09/"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-10.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-10/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1585.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0051.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0053.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0054.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0055.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0056.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0057.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0058.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0059.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0061.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0062.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7371.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/21");
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
if (rpm_check(release:"SLED10", sp:3, reference:"MozillaFirefox-3.6.15-0.6.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"MozillaFirefox-translations-3.6.15-0.6.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"mozilla-xulrunner192-1.9.2.15-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"mozilla-xulrunner192-gnome-1.9.2.15-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"mozilla-xulrunner192-translations-1.9.2.15-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.15-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.15-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner192-translations-32bit-1.9.2.15-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"MozillaFirefox-3.6.15-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"MozillaFirefox-translations-3.6.15-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-xulrunner192-1.9.2.15-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-xulrunner192-gnome-1.9.2.15-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-xulrunner192-translations-1.9.2.15-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.15-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.15-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner192-translations-32bit-1.9.2.15-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
