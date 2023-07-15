#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100956);
  script_version("1.2");
  script_cvs_date("Date: 2018/09/04 16:39:50");

  script_name(english:"AgileBits 1Password 6.3.3 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of AgileBits 1Password.");

  script_set_attribute(attribute:"synopsis", value:
"A password management application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of AgileBits 1Password installed on the remote macOS or
Mac OS X host is equal to 6.3.3. It is, therefore, affected by
multiple vulnerabilities :

  - A security weakness exists in the internal web browser
    in which the default protocol that is used is set to
    HTTP. If a user visits a website without specifying the
    full URL, the more secure HTTPS protocol will not be
    used even if it is available. A man-in-the-middle
    attacker can exploit this to disclose sensitive
    information. (SIK-2016-039)

  - A security weakness exists in the database of the
    password manager due to lack of encryption for titles
    and URLs. An attacker who is able to obtain a copy of
    the encrypted database can exploit this to disclose the
    websites for which the user has stored credentials
    without having to break the cryptography. (SIK-2016-040)

  - A security weakness exists in the password manager due
    to sending the target domain to the vendor's web server
    in order to obtain from a server-side cache an icon that
    represents the respective target website. This issue
    allows the vendor to track all the sites for which the
    user has created database entries. (SIK-2016-042)");
  # https://www.theregister.co.uk/2017/02/28/flaws_in_password_management_apps/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eedc9d32");
  script_set_attribute(attribute:"see_also", value:"https://team-sik.org/sik-2016-039/");
  script_set_attribute(attribute:"see_also", value:"https://team-sik.org/sik-2016-040/");
  script_set_attribute(attribute:"see_also", value:"https://team-sik.org/sik-2016-042/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of AgileBits 1Password that is later than 6.3.3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"An in depth analysis by Tenable researchers revealed the Access Complexity to be high.");
  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:agilebits:1password");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_agilebits_1password_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/1Password");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");
include("vcf.inc");
include("vcf_extras.inc");

app_name = "1Password";
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item('Host/MacOSX/Version');
if (!os) audit(AUDIT_OS_NOT, 'Mac OS X or macOS');

vcf::agilebit_1password::initialize();

app_info = vcf::get_app_info(app:app_name);

constraints = [
  { "min_version" : "6.0", "max_version" : "6.3.3", "fixed_version" : "See Solution" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE);
