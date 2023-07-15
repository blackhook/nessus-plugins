#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170121);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/02");

  script_cve_id("CVE-2022-43649");
  script_xref(name:"IAVA", value:"2023-A-0128-S");

  script_name(english:"Foxit PDF Reader < 12.1 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote Windows host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PDF Reader application (previously named Foxit Reader) installed on the remote
Windows host is prior to 12.1. It is, therefore affected by vulnerability:

  - This vulnerability allows remote attackers to execute arbitrary code on affected installations of Foxit
    PDF Reader 12.0.2.12465. User interaction is required to exploit this vulnerability in that the target
    must visit a malicious page or open a malicious file. The specific flaw exists within the handling of
    Annotation objects. The issue results from the lack of validating the existence of an object prior to
    performing operations on the object. An attacker can leverage this vulnerability to execute code in the
    context of the current process. Was ZDI-CAN-19478. (CVE-2022-43649)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PDF Reader version 12.1 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-43649");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_reader_installed.nasl");
  script_require_keys("installed_sw/Foxit Reader", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Foxit Reader', win_local:TRUE);

var constraints = [
  { 'max_version' : '12.0.2.12465', 'fixed_version' : '12.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
