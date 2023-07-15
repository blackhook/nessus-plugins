#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140605);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/22");

  script_cve_id(
    "CVE-2020-9727",
    "CVE-2020-9728",
    "CVE-2020-9729",
    "CVE-2020-9730",
    "CVE-2020-9731"
  );
  script_bugtraq_id(107821);
  script_xref(name:"IAVA", value:"2020-A-0428-S");

  script_name(english:"Adobe InDesign CC < 15.1.2 Arbitrary Code Execution (APSB20-52) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InDesign installed on the remote macOS or Mac OS X host is prior to 15.1.2. It is, therefore,
affected by an arbitrary code execution vulnerability that exists due to insecure handling of indd files. An attacker
can exploit this issue to cause an out-of-bounds memory access, potentially resulting in code execution in the
context of the current user.");
  # https://helpx.adobe.com/security/products/indesign/apsb20-52.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba6eed03");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe InDesign version 15.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9727");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:indesign");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_indesign_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe InDesign");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version')) audit(AUDIT_OS_NOT, 'Mac OS X');

app = 'Adobe InDesign';
app_info = vcf::get_app_info(app:app);

constraints = [
  { 'min_version' : '15', 'fixed_version' : '15.1.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

