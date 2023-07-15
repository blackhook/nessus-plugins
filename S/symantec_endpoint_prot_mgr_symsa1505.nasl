#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133676);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/25");

  script_cve_id(
    "CVE-2020-5827",
    "CVE-2020-5828",
    "CVE-2020-5829",
    "CVE-2020-5830",
    "CVE-2020-5831"
  );
  script_bugtraq_id(
    111781,
    111782,
    111785,
    111786,
    111787
  );
  script_xref(name:"IAVA", value:"2020-A-0060-S");

  script_name(english:"Symantec Endpoint Protection Manager 14.x < 14.2 RU2 MP1 Multiple Out-of-Bounds Read Vulnerabilities (SYMSA1505)");
  script_summary(english:"Checks the SEPM version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Symantec Endpoint Protection Manager installed on the
remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection Manager (SEPM) installed
on the remote host is 14.x prior to 14.2 RU2 MP1. It is, therefore,
affected by multiple out-of-bounds read vulnerabilities. 

An unauthenticated, remote attacker can exploit this to read memory 
outside of the bounds of the memory that had been allocated to the 
program. (CVE-2020-5827, CVE-2020-5828, CVE-2020-5829, 
CVE-2020-5830, CVE-2020-5831)");
  # https://support.symantec.com/en_US/article.SYMSA1505.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ad00a7d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Endpoint Protection Manager version 14.2 RU2 MP1
or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5831");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_endpoint_prot_mgr_installed.nasl");
  script_require_keys("installed_sw/Symantec Endpoint Protection Manager");

  exit(0);
}

include('vcf.inc');

# Define constraints for version check
constraints = [
  {
    'fixed_version' : '14.2.5569.2100',
    'min_version'   : '14.1'
  }
];

# Get application info
app_info = vcf::get_app_info(app:'Symantec Endpoint Protection Manager', win_local:TRUE);

# Do version check using app_info
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
