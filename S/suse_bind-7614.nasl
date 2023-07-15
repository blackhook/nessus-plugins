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
  script_id(57161);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2011-2464");

  script_name(english:"SuSE 10 Security Update : bind (ZYPP Patch Number 7614)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A remote denial of service vulnerability has been fixed in bind.
Specially crafted packets could cause bind servers (recursive as well
as authoritative) to exit."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2464.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7614.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/06");
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
if (rpm_check(release:"SLED10", sp:4, reference:"bind-libs-9.6ESVR4P3-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"bind-utils-9.6ESVR4P3-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"bind-libs-32bit-9.6ESVR4P3-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"bind-9.6ESVR4P3-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"bind-chrootenv-9.6ESVR4P3-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"bind-devel-9.6ESVR4P3-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"bind-doc-9.6ESVR4P3-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"bind-libs-9.6ESVR4P3-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"bind-utils-9.6ESVR4P3-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"bind-libs-32bit-9.6ESVR4P3-0.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
