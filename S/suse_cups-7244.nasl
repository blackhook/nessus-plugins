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
  script_id(50984);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-0542", "CVE-2010-1748", "CVE-2010-3702", "CVE-2010-3703");

  script_name(english:"SuSE 10 Security Update : CUPS (ZYPP Patch Number 7244)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following vulnerabilities in cups :

  - A specially crafted PDF file could crash the pdftops
    potentially even cause execution of arbitrary code.
    (CVE-2010-3702: CVSS v2 Base Score: 5.8).
    (CVE-2010-3702)

  - A NULL pointer dereference issue exists in the
    _WriteProlog function of texttops. (CVE-2010-0542: CVSS
    v2 Base Score: 6.8: Permissions, Privileges, and Access
    Control (CWE-264)). (CVE-2010-0542)

  - Memory disclosure in web interface. (CVE-2010-1748: CVSS
    v2 Base Score: 4.3: Buffer Errors (CWE-119)).
    (CVE-2010-1748)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0542.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1748.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3702.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3703.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7244.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SLED10", sp:3, reference:"cups-1.1.23-40.60.12")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"cups-client-1.1.23-40.60.12")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"cups-devel-1.1.23-40.60.12")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"cups-libs-1.1.23-40.60.12")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"cups-libs-32bit-1.1.23-40.60.12")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"cups-1.1.23-40.60.12")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"cups-client-1.1.23-40.60.12")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"cups-devel-1.1.23-40.60.12")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"cups-libs-1.1.23-40.60.12")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"cups-libs-32bit-1.1.23-40.60.12")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
