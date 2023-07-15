#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112193);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/17");

  script_cve_id("CVE-2018-11048");
  script_bugtraq_id(105130);
  script_xref(name:"IAVB", value:"2018-B-0118-S");

  script_name(english:"EMC Data Protection Advisor 6.2 < 6.4 Patch B180 / < 6.5 patch B51 (DSA-2018-112).");
  script_summary(english:"Checks EMC Data Protection Advisor version");

  script_set_attribute(attribute:"synopsis", value:
"The remote application may be affected by XML External Entity
Vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the application is
6.2 < 6.4 Patch B180 or 6.5 < 6.5 patch B51. It is, therefore,
affected by an XML external entity vulnerability vulnerability.");
  # https://support.emc.com/downloads/829_Data-Protection-Advisor
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf340180");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2018/Aug/5");
  script_set_attribute(attribute:"solution", value:
"Upgrade EMC Data Protection Advisor to version 6.4 Patch B180 or
6.5 patch B51 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11048");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:data_protection_advisor");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("win_emc_dpa_installed.nbin");
  script_require_keys("installed_sw/EMC Data Protection Advisor");

  exit(0);
}


include("vcf.inc");
include("audit.inc");

app_name = "EMC Data Protection Advisor";
app_info = vcf::get_app_info(app:app_name);
vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "min_version" : "6.2", "fixed_version" : "6.4.0.103564" },
  { "min_version" : "6.5", "fixed_version" : "6.5.0.103604" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
