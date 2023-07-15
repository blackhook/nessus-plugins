#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(51747);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-1570", "CVE-2009-3909");

  script_name(english:"SuSE 10 Security Update : gimp (ZYPP Patch Number 6882)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Integer overflows in the BMP and PSD plug-ins potentially allowed
attackers to execute arbitrary code on the victim's system by tricking
the victim to open specially crafted files. 

  - CVE-2009-3909: CVSS v2 Base Score: 4.3 (moderate)
    (AV:N/AC:M/Au:N/C:N/I:N/A:P): Numeric Errors. (CWE-189).
    (CVE-2009-1570: CVSS v2 Base Score: 4.3 (moderate)
    (AV:N/AC:M/Au:N/C:N/I:N/A:P)). (- Numeric Errors
    (CWE-189))"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1570.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3909.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6882.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"gimp-2.2.10-22.33.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"gimp-devel-2.2.10-22.33.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"gimp-2.2.10-22.32")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"gimp-devel-2.2.10-22.32")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");