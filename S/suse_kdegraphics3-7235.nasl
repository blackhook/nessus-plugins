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
  script_id(51113);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-0945", "CVE-2009-1709", "CVE-2010-3702", "CVE-2010-3703", "CVE-2010-3704");

  script_name(english:"SuSE 10 Security Update : kdegraphics (ZYPP Patch Number 7235)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Various pointer dereferencing vulnerabilities in kdegraphics3's KSVG
have been fixed. CVE-2009-1709 / CVE-2009-0945 have been assigned to
this issue.

Also specially crafted PDF files could crash kpdf or potentially even
cause execution of arbitrary code. (CVE-2010-3702 / CVE-2010-3703 /
CVE-2010-3704)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0945.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1709.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3702.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3703.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3704.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7235.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(94, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:3, reference:"kdegraphics3-3.5.1-23.30.4")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"kdegraphics3-devel-3.5.1-23.30.4")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"kdegraphics3-fax-3.5.1-23.30.4")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"kdegraphics3-kamera-3.5.1-23.30.4")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"kdegraphics3-pdf-3.5.1-23.30.4")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"kdegraphics3-postscript-3.5.1-23.30.4")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"kdegraphics3-scan-3.5.1-23.30.4")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"kdegraphics3-3.5.1-23.30.4")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"kdegraphics3-devel-3.5.1-23.30.4")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"kdegraphics3-extra-3.5.1-23.30.4")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"kdegraphics3-fax-3.5.1-23.30.4")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"kdegraphics3-pdf-3.5.1-23.30.4")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"kdegraphics3-postscript-3.5.1-23.30.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
