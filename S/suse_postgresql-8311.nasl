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
  script_id(62545);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2011-2483", "CVE-2012-2655", "CVE-2012-3488", "CVE-2012-3489");

  script_name(english:"SuSE 10 Security Update : PostgreSQL (ZYPP Patch Number 8311)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"PostgreSQL was updated to the latest stable release 8.1.23, fixing
various bugs and security issues.

The following security issues have been fixed :

  - This update fixes arbitrary read and write of files via
    XSL functionality. (CVE-2012-3488)

  - postgresql: denial of service (stack exhaustion) via
    specially crafted SQL. (CVE-2012-2655)

  - crypt_blowfish was mishandling 8 bit characters.
    (CVE-2011-2483)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2483.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2655.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3488.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3489.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8311.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/15");
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
if (rpm_check(release:"SLED10", sp:4, reference:"postgresql-devel-8.1.23-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"postgresql-libs-8.1.23-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"postgresql-libs-32bit-8.1.23-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"postgresql-8.1.23-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"postgresql-contrib-8.1.23-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"postgresql-devel-8.1.23-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"postgresql-docs-8.1.23-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"postgresql-libs-8.1.23-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"postgresql-pl-8.1.23-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"postgresql-server-8.1.23-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"postgresql-libs-32bit-8.1.23-0.11.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
