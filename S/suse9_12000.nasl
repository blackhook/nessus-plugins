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
  script_id(41170);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2005-4872", "CVE-2006-7227", "CVE-2006-7228", "CVE-2007-1660");

  script_name(english:"SuSE9 Security Update : Apache 2 (YOU Patch Number 12000)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Apache2 contains a copy of the pcre library. Specially crafted regular
expressions could lead to a buffer overflow in the pcre library.
Applications using pcre to process regular expressions from untrusted
sources could therefore potentially be exploited by attackers to
execute arbitrary code. (CVE-2006-7224, CVE-2007-1660)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-7224.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-1660.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12000.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/06");
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
if (rpm_check(release:"SUSE9", reference:"apache2-2.0.59-1.6")) flag++;
if (rpm_check(release:"SUSE9", reference:"apache2-devel-2.0.59-1.6")) flag++;
if (rpm_check(release:"SUSE9", reference:"apache2-doc-2.0.59-1.6")) flag++;
if (rpm_check(release:"SUSE9", reference:"apache2-example-pages-2.0.59-1.6")) flag++;
if (rpm_check(release:"SUSE9", reference:"apache2-prefork-2.0.59-1.6")) flag++;
if (rpm_check(release:"SUSE9", reference:"apache2-worker-2.0.59-1.6")) flag++;
if (rpm_check(release:"SUSE9", reference:"libapr0-2.0.59-1.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
