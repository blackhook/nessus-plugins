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
  script_id(58722);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2012-1126", "CVE-2012-1127", "CVE-2012-1129", "CVE-2012-1130", "CVE-2012-1131", "CVE-2012-1132", "CVE-2012-1133", "CVE-2012-1134", "CVE-2012-1135", "CVE-2012-1136", "CVE-2012-1137", "CVE-2012-1138", "CVE-2012-1139", "CVE-2012-1141", "CVE-2012-1142", "CVE-2012-1143");

  script_name(english:"SuSE 10 Security Update : freetype2 (ZYPP Patch Number 8039)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Specially crafted font files could have caused buffer overflows in
freetype. This has been fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1126.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1127.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1129.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1130.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1131.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1132.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1133.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1134.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1135.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1136.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1137.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1138.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1139.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1141.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1142.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1143.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8039.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SLED10", sp:4, reference:"freetype2-2.1.10-18.29.6")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"freetype2-devel-2.1.10-18.29.6")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"ft2demos-2.1.10-19.29.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"freetype2-32bit-2.1.10-18.29.6")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"freetype2-devel-32bit-2.1.10-18.29.6")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"freetype2-2.1.10-18.29.6")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"freetype2-devel-2.1.10-18.29.6")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"ft2demos-2.1.10-19.29.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"freetype2-32bit-2.1.10-18.29.6")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"freetype2-devel-32bit-2.1.10-18.29.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
