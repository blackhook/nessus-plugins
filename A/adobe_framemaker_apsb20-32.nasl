#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137362);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/11");

  script_cve_id("CVE-2020-9634", "CVE-2020-9635", "CVE-2020-9636");
  script_xref(name:"IAVB", value:"2020-B-0032-S");

  script_name(english:"Adobe FrameMaker < 15.0.6 (aka 2019.0.6) Multiple Vulnerabilities (APSB20-32)");

  script_set_attribute(attribute:"synopsis", value:
"The remote install of Adobe FrameMaker has Multiple Vulnerabilities (APSB20-32).");
  script_set_attribute(attribute:"description", value:
"The version of Adobe FrameMaker installed on the remote Windows host
is prior to 15.0.6 . It is, therefore, affected by a the following
vulnerabilities :

  - An unspecified memory corruption error exists that allows
    arbitrary code execution (CVE-2020-9634)

  - An unspecified out of bounds error exists that allows
    arbitrary code execution. (CVE-2020-9635, CVE-2020-9636)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/framemaker/apsb20-32.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe FrameMaker 15.0.6 (aka 2019.0.6) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9636");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:framemaker");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_framemaker_installed.nbin");
  script_require_keys("installed_sw/Adobe FrameMaker", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
app_info = vcf::get_app_info(app:"Adobe FrameMaker", win_local:TRUE);

# fixed is 15.0.6 (aka 2019.0.6)
constraints = [{"fixed_version":"15.0.6", "fixed_display":"15.0.6 (aka 2019.0.6)"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
