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
  script_id(57218);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2008-6218", "CVE-2009-5063", "CVE-2011-2501", "CVE-2011-2690", "CVE-2011-2691", "CVE-2011-2692");

  script_name(english:"SuSE 10 Security Update : libpng (ZYPP Patch Number 7670)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of libpng fixes :

  - CVE-2008-6218: CVSS v2 Base Score: 7.1
    (AV:N/AC:M/Au:N/C:N/I:N/A:C): Resource Management Errors
    (CWE-399)

  - CVE-2011-2690: CVSS v2 Base Score: 5.1
    (AV:N/AC:H/Au:N/C:P/I:P/A:P): Buffer Errors (CWE-119)

  - CVE-2011-2692: CVSS v2 Base Score: 5.0
    (AV:N/AC:M/Au:N/C:N/I:N/A:P): Buffer Errors (CWE-119)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-6218.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-5063.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2501.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2690.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2691.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2692.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7670.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/03");
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
if (rpm_check(release:"SLED10", sp:4, reference:"libpng-1.2.8-19.31.9")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libpng-devel-1.2.8-19.31.9")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"libpng-32bit-1.2.8-19.31.9")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"libpng-devel-32bit-1.2.8-19.31.9")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"libpng-1.2.8-19.31.9")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"libpng-devel-1.2.8-19.31.9")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"libpng-32bit-1.2.8-19.31.9")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"libpng-devel-32bit-1.2.8-19.31.9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
