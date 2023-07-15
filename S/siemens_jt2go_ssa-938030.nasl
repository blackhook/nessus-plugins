#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152659);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/16");

  script_cve_id("CVE-2021-32946", "CVE-2021-32952", "CVE-2021-33738");
  script_xref(name:"IAVA", value:"2021-A-0388-S");

  script_name(english:"Siemens JT2Go < 13.2.0.2 Multiple Vulnerabilities (SSA-938030)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Siemens JT2Go installed on the remote Windows hosts is prior to 13.2.0.2. It is, therefore, affected by
multiple vulnerabilities, including the following:

  - An improper check for unusual or exceptional conditions issue exists within the parsing DGN files
    from Open Design Alliance Drawings SDK (Version 2022.4 and prior) resulting from the lack of proper
    validation of the user-supplied data. This may result in several of out-of-bounds problems and allow
    attackers to cause a denial-of-service condition or execute code in the context of the current process.
    (CVE-2021-32946)

  - An out-of-bounds write issue exists in the DGN file-reading procedure in the Drawings SDK (Version
    2022.4 and prior) resulting from the lack of proper validation of user-supplied data. This can result in a
    write past the end of an allocated buffer and allow attackers to cause a denial-of-service condition or
    execute code in the context of the current process. (CVE-2021-32952)

  - The plmxmlAdapterSE70.dll library in affected applications lacks proper validation of user-supplied
    data when parsing PAR files. This could result in an out of bounds read past the end of an allocated
    buffer. An attacker could leverage this vulnerability to leak information in the context of the current
    process. (CVE-2021-33738)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://cert-portal.siemens.com/productcert/pdf/ssa-938030.pdf");
  script_set_attribute(attribute:"solution", value:
"Update JT2Go to version 13.2.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32946");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:siemens:jt2go");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("siemens_jt2go_win_installed.nbin");
  script_require_keys("installed_sw/Siemens JT2Go", "SMB/Registry/Enumerated");

  exit(0);
}
include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Siemens JT2Go', win_local:TRUE);
var constraints = [{'fixed_version': '13.2.0.21176', 'fixed_display': '13.2.0.2'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
