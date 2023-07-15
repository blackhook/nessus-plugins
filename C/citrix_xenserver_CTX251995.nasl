#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(125549);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-12126",
    "CVE-2018-12127",
    "CVE-2018-12130",
    "CVE-2019-11091"
  );
  script_bugtraq_id(108330);
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");
  script_xref(name:"CEA-ID", value:"CEA-2019-0324");

  script_name(english:"Citrix XenServer Microarchitectural Data Sampling Speculative Side-Channel Vulnerabilities (MDSUM/RIDL) (MFBDS/RIDL/ZombieLoad) (MLPDS/RIDL) (MSBDS/Fallout) (CTX2251995)");

  script_set_attribute(attribute:"synopsis", value:
"A server virtualization platform installed on the remote host is
missing a security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer running on the remote host is missing
a security hotfix. It is, therefore, affected by microarchitectural
data sampling speculative side-channel vulnerabilities. These
vulnerabilities may allow a local attacker on a guest machine to
sample the contents of memory reads and writes. Please refer to the
vendor advisory for mitigating factors.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX251995");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11091");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:xenserver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_xenserver_version.nbin");
  script_require_keys("Host/XenServer/version");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

app_info = vcf::xenserver::get_app_info();

constraints = [
  { "equal" : "7.0",    "patches" :           # XenServer 7.0
                          ["XS70E068"] },     # CTX250038
  { "equal" : "7.1.2",  "patches" :           # XenServer 7.1 LTSR CU2
                          ["XS71ECU2008"] },  # CTX250039
  { "equal" : "7.6",    "patches" :           # XenServer 7.6
                          ["XS76E004"] },     # CTX250040
  { "equal" : "8.0",    "patches" :           # XenServer 8.0
                          ["XS80E001"] }      # CTX250041
];

vcf::xenserver::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
