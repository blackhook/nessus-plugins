#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136620);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2020-5833", "CVE-2020-5834", "CVE-2020-5835");
  script_xref(name:"IAVA", value:"2020-A-0210");

  script_name(english:"Symantec Endpoint Protection Manager < 14.3 Multiple Vulnerabilities (SYMSA1762)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Symantec Endpoint Protection Manager installed on the remote host is affected by multiple 
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection Manager (SEPM) installed on the remote host is prior to 14.3. It is
therefore affected by the following vulnerabilities:

  - An out of bounds read error exists. An authenticated, local attacker can exploit this issue to disclose
    memory contents. (CVE-2020-5833)

  - A directory traversal vulnerability exists. An unauthenticated, remote attacker can exploit this issue to
    determine the size of files in a directory. (CVE-2020-5834)

  - An elevation of privilege vulnerability exists due to a race condition in client remote deployment. An
    authenticated, local attacker can exploit this issue to gain elevated privileges. (CVE-2020-5835)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.broadcom.com/security-advisory/security-advisory-detail.html?notificationId=SYMSA1762
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54057529");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Endpoint Protection Manager version 14.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5834");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-5835");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_endpoint_prot_mgr_installed.nasl");
  script_require_keys("installed_sw/Symantec Endpoint Protection Manager");

  exit(0);
}

include("vcf.inc");

constraints = [
  { "fixed_version" : "14.3.558.0000" }
];

app_info = vcf::get_app_info(app:'Symantec Endpoint Protection Manager', win_local:TRUE);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
