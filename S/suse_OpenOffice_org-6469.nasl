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
  script_id(51683);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-0200", "CVE-2009-0201");

  script_name(english:"SuSE 10 Security Update : OpenOffice_org (ZYPP Patch Number 6469)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of OpenOffice.org fixes potential buffer overflow in EMF
parser code (enhwmf.cxx, emfplus.cxx). Additionally Secunia reported
an integer underflow (CVE-2009-0200) and a buffer overflow
(CVE-2009-0201) that could be triggered while parsing Word documents.

Also provides the maintenance update to OpenOffice.org-3.1.1."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0200.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0201.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6469.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/28");
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
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-af-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-ar-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-ca-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-cs-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-da-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-de-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-el-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-en-GB-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-es-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-fi-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-fr-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-galleries-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-gnome-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-gu-IN-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-hi-IN-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-hu-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-it-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-ja-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-kde-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-ko-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-mono-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-nb-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-nl-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-nld-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-nn-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-pl-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-pt-BR-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-ru-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-sk-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-sv-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-xh-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-zh-CN-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-zh-TW-3.1.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"OpenOffice_org-zu-3.1.1-0.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
