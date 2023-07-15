#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(136664);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-1173");
  script_xref(name:"IAVB", value:"2020-B-0027-S");

  script_name(english:"Security Update for Microsoft Power BI Report Server (May 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is missing a security update.");
  script_set_attribute(attribute:"description", value:
"A spoofing vulnerability exists in Microsoft Power BI Report Server in the way 
it validates the content-type of uploaded attachments. An authenticated attacker could 
exploit the vulnerability by uploading a specially crafted payload and sending it to the user.

The attacker who successfully exploited this vulnerability could then perform actions 
and run scripts in the security context of the user.

This security update addresses the vulnerability by ensuring Power BI Report Server 
properly validates content-type of the attachments when uploading and opening.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1173
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dde4bbb9");
  script_set_attribute(attribute:"solution", value:
"Upgrade Power BI Report Server to version 1.6.7236.4246 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1173");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:power_bi_report_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_power_bi_rs_win_installed.nbin");
  script_require_keys("installed_sw/Microsoft Power BI Report Server");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Microsoft Power BI Report Server', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:4);

constraints = [
  { 'min_version': '1.5.7074.36177' ,'fixed_version' : '1.6.7236.4246' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
