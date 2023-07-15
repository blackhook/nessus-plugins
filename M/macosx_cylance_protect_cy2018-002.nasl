#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109597);
  script_version("1.1");
  script_cvs_date("Date: 2018/05/07 18:43:35");

  script_xref(name:"TRA", value:"TRA-2018-12");

  script_name(english:"CylancePROTECT 2.0.x < 2.0.1480 SSL Validation (Cy2008-002) (macOS)");
  script_summary(english:"Checks the version of CylancePROTECT.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote MacOS / MacOSX host is
affected by an SSL validation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of CylancePROTECT installed on the remote MacOS/MacOSX
host is 2.0.x prior to 2.0.1480. It is, therefore, affected by an SSL
validation flaw that can allow an attacker to cause an arbitrary file
download.");
  # https://threatmatrix.cylance.com/en_us/home/cylanceprotect-vulnerability-disclosure-and-policies.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d26ea478");
  script_set_attribute(attribute:"solution", value:
"Upgrade to CylancePROTECT version 2.0.1480 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cylance:cylanceprotect");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_cylance_protect_installed.nbin");
  script_require_keys("installed_sw/CylancePROTECT", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("Host/MacOSX/Version");

app_info = vcf::get_app_info(app:"CylancePROTECT");

constraints = [
  { "min_version" : "2.0", "fixed_version" : "2.0.1480" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
