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
  script_id(34844);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-2237", "CVE-2008-2238");

  script_name(english:"SuSE 10 Security Update : OpenOffice_org (ZYPP Patch Number 5740)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes an integer overflow in the WMF handler
(CVE-2008-2237) and multiple bugs in the EMF parser (CVE-2008-2238).
Additionally multiple non-security bugs were fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2237.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2238.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 5740.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-af-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-ar-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-ca-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-cs-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-da-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-de-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-es-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-fi-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-fr-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-galleries-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-gnome-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-gu-IN-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-hi-IN-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-hu-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-it-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-ja-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-kde-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-mono-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-nb-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-nl-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-nld-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-nn-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-pl-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-pt-BR-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-ru-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-sk-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-sv-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-xh-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-zh-CN-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-zh-TW-2.4.1-0.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"OpenOffice_org-zu-2.4.1-0.8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
