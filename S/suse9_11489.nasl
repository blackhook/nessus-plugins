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
  script_id(41124);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2005-3352");

  script_name(english:"SuSE9 Security Update : Apache (YOU Patch Number 11489)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes a missed security update for Apache 1.3. The
problem is already fixed for our Apache2 packages.

  - mod_imap: Escape untrusted Referer header before
    outputting in HTML to avoid potential cross-site
    scripting. A change was also made to ap_escape_html so
    we escape quotes. (CVE-2005-3352)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2005-3352.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 11489.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/23");
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
if (rpm_check(release:"SUSE9", reference:"apache-1.3.29-71.24")) flag++;
if (rpm_check(release:"SUSE9", reference:"apache-devel-1.3.29-71.24")) flag++;
if (rpm_check(release:"SUSE9", reference:"mod_ssl-2.8.16-71.24")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
