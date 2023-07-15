#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(147716);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/16");

  script_cve_id("CVE-2021-21056");
  script_xref(name:"IAVB", value:"2021-B-0015-S");

  script_name(english:"Adobe FrameMaker < 16.0.2 (aka 2020.0.2) Arbitrary code execution (APSB21-14)");

  script_set_attribute(attribute:"synopsis", value:
"The remote install of Adobe FrameMaker has arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe FrameMaker installed on the remote Windows host is prior to 16.0.2 (aka 2020.0.2). It is, therefore, affected by
the an unspecified out of bounds read error that allows arbitrary code execution.
    
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/framemaker/apsb21-14.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe FrameMaker 16.0.2 (aka 2020.0.2) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21056");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:framemaker");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_framemaker_installed.nbin");
  script_require_keys("installed_sw/Adobe FrameMaker", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
app_info = vcf::get_app_info(app:'Adobe FrameMaker', win_local:TRUE);

# 16.0.2 (aka 2020.0.2)
constraints = [{'max_version': '15.0.9', 'fixed_display':'16.0.2 (aka 2020.0.2)'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

