#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##


# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152428);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/22");

  script_cve_id("CVE-2021-36949");
  script_xref(name:"IAVA", value:"2021-A-0433");

  script_name(english:"Security Update for Microsoft Azure Active Directory Connect (August 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An authentication bypass exists in Microsoft Azure Active Directory Connect. An attacker with domain user credentials
may perform a man-in-the-middle between a domain controller and the Azure AD Connect server to exploit this
vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36949
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?beec548c");
  # https://docs.microsoft.com/en-us/azure/active-directory/hybrid/reference-connect-version-history
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67116170");
  script_set_attribute(attribute:"solution", value:
"Upgrade Azure Active Directory Connect to version 1.6.11.3, 2.0.8.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36949");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:azure_active_directory_connect");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_azure_ad_connect_installed.nbin");
  script_require_keys("installed_sw/Microsoft Azure AD Connect");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Microsoft Azure AD Connect', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:4);

var constraints = [
  { 'min_version': '0.0.0.0' ,'fixed_version' : '1.6.11.3' },
  { 'min_version': '2.0.0.0' ,'fixed_version' : '2.0.8.0' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
