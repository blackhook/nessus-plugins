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
  script_id(41152);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-4137");

  script_name(english:"SuSE9 Security Update : qt3 (YOU Patch Number 11795)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An off-by-one error in the QUtf8Decoder::toUnicode() method has been
found which may allow a denial of service attack with specially
crafted UTF-8 character sequences that trigger a buffer overflow.
(CVE-2007-4137)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-4137.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 11795.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 Tenable Network Security, Inc.");
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
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 9 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SUSE9", reference:"qt3-3.3.1-36.31")) flag++;
if (rpm_check(release:"SUSE9", reference:"qt3-devel-3.3.1-36.31")) flag++;
if (rpm_check(release:"SUSE9", reference:"qt3-devel-doc-3.3.1-36.31")) flag++;
if (rpm_check(release:"SUSE9", reference:"qt3-devel-tools-3.3.1-35.24")) flag++;
if (rpm_check(release:"SUSE9", reference:"qt3-non-mt-3.3.1-41.29")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"qt3-32bit-9-200709191359")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"qt3-devel-32bit-9-200709191359")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
