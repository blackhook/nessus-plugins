##
# (C) Tenable Network Security, Inc.
##


# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(147657);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/19");

  script_cve_id("CVE-2021-26859");
  script_xref(name:"MSKB", value:"5001284");
  script_xref(name:"MSKB", value:"5001285");
  script_xref(name:"MSFT", value:"MS21-5001284");
  script_xref(name:"MSFT", value:"MS21-5001285");
  script_xref(name:"IAVB", value:"2021-B-0018");

  script_name(english:"Security Update for Microsoft Power BI Report Server (March 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An information disclosure vulnerability exists in Microsoft Power BI Report Server due to excessive data output by the
application in Microsoft Power BI. An authenticated, remote attacker can exploit this, to disclose potentially sensitive
information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26859
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3bca0101");
  script_set_attribute(attribute:"solution", value:
"Upgrade Power BI Report Server to version 15.0.1103.241, 15.0.1104.310 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26859");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:power_bi_report_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_power_bi_rs_win_installed.nbin");
  script_require_keys("installed_sw/Microsoft Power BI Report Server");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Microsoft Power BI Report Server', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:4);

constraints = [
  { 'min_version': '0' ,'fixed_version' : '1.8.7710.3956' },
  { 'min_version': '1.9' ,'fixed_version' : '1.9.7709.41358' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
