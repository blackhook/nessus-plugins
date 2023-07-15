#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169989);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/16");

  script_cve_id("CVE-2023-21601", "CVE-2023-21603");
  script_xref(name:"IAVA", value:"2023-A-0023-S");

  script_name(english:"Adobe Dimension < 3.4.7 Multiple Vulnerabilities (APSB23-10)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Dimension installed on the remote host is prior to 3.4.7.
It is, therefore, affected by multiple vulnerabilities, including the following:

- An information disclosure vulnerability exists caused by use of
previously-freed memory. An unauthenticated, local attacker can exploit this,
via a memory leak, to potentially divulge sensitive information.
(CVE-2023-21601)

- An information disclosure vulnerability exists caused by out-of-bounds reads.
An unauthenticated, local attacker can exploit this, via a memory leak, to
potentially divulge sensitive information. (CVE-2023-21603)

Note that Nessus has not attempted to exploit these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/dimension/apsb23-10.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Dimension version 3.4.7 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21601");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:dimension");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_dimension_installed.nbin", "macos_adobe_dimension_installed.nbin");
  script_require_keys("installed_sw/Adobe Dimension");

  exit(0);
}

include('vcf.inc');

var win_local = FALSE;

if (get_kb_item('SMB/Registry/Enumerated'))
  win_local = TRUE;

var app_info = vcf::get_app_info(app:'Adobe Dimension', win_local:win_local);

var constraints = [
  { 'fixed_version' : '3.4.7'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
