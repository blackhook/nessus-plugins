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
  script_id(34076);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-2935");

  script_name(english:"SuSE 10 Security Update : libxslt (ZYPP Patch Number 5457)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A heap overflow in the RC4 cryptographic routines in libxslt was fixed
which could be used by attackers to potentially execute code.
(CVE-2008-2935)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2935.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 5457.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/03");
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
if (rpm_check(release:"SLED10", sp:1, reference:"libxslt-1.1.15-15.11")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"libxslt-devel-1.1.15-15.11")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"libxslt-32bit-1.1.15-15.11")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"libxslt-devel-32bit-1.1.15-15.11")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"libxslt-1.1.15-15.11")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"libxslt-devel-1.1.15-15.11")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"libxslt-32bit-1.1.15-15.11")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"libxslt-devel-32bit-1.1.15-15.11")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"libxslt-1.1.15-15.11")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"libxslt-devel-1.1.15-15.11")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"libxslt-32bit-1.1.15-15.11")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"libxslt-devel-32bit-1.1.15-15.11")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"libxslt-1.1.15-15.11")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"libxslt-devel-1.1.15-15.11")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"libxslt-32bit-1.1.15-15.11")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"libxslt-devel-32bit-1.1.15-15.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
