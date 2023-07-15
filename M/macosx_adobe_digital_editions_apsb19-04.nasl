#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121127);
  script_version("1.4");
  script_cvs_date("Date: 2019/10/31 15:18:51");

  script_cve_id("CVE-2018-12817");
  script_bugtraq_id(106472);

  script_name(english:"Adobe Digital Editions < 4.5.10 Out-Of-Bounds Read Vulnerability (APSB19-04) (Mac OS X)");
  script_summary(english:"Checks the version of Mac OS X Adobe Digital Editions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host is affected by out-of-bounds read vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Digital Editions installed on the remote Mac OS X
host is prior to 4.5.10. It is, therefore, affected by an 
out-of-bounds read vulnerability.");
  # https://helpx.adobe.com/security/products/Digital-Editions/apsb19-04.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1381b93b");
  # http://www.adobe.com/solutions/ebook/digital-editions/release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3aa2f29");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Digital Editions version 4.5.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12817");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:digital_editions");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_digital_editions_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Digital Editions");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"Adobe Digital Editions", win_local:TRUE);

constraints = [
  { "fixed_version" : "4.5.10" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
