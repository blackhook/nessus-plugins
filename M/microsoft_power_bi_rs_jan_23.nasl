#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171549);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/20");

  script_cve_id("CVE-2023-21806");
  script_xref(name:"IAVA", value:"2023-A-0093");

  script_name(english:"Security Update for Microsoft Power BI Report Server (January 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Power BI Report Server on the remote host is missing the January 2023 security update. It is, therefore,
affected by a spoofing vulnerability that can result in escalation of privilege. An authenticated, remote attacker can,
by tricking a user into opening a malicious file on the server, retrieve that user's cookies or present the user with
a dialog box to enter user credentials.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5023884");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21806
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?261f664b");
  script_set_attribute(attribute:"solution", value:
"Upgrade Power BI Report Server to version 1.16.8420.13742 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21806");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:power_bi_report_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_power_bi_rs_win_installed.nbin");
  script_require_keys("installed_sw/Microsoft Power BI Report Server");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Microsoft Power BI Report Server', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:4);

var constraints = [
  { 'min_version': '1.14.8179.37378' ,'fixed_version' : '1.16.8420.13742' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
