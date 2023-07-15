#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(500659);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/27");

  script_cve_id("CVE-2022-29951",
                "CVE-2022-29958");   

  script_name(english:"JTEKT TOYOPUC OT:ICEFALL Multiple Potential Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote OT asset may be affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The device may be vulnerable to flaws related to OT:ICEFALL. These vulnerabilities
identify the insecure-by-design nature of OT devices and may not have a clear
remediation path. As such, Nessus is unable to test specifically for these
vulnerabilities but has identified the device to be one that was listed in the
OT:ICEFALL report. Ensure your OT deployments follow best practices including
accurate inventory, separation of environments, and monitoring. This plugin will
trigger on any device seen by Tenable.OT that matches a family or model listed
in the OT:ICEFALL report.

Note: All findings need to be manually verified based on the advisory from the vendor, once released.

This plugin only works with Tenable.ot. Please visit
https://www.tenable.com/products/tenable-ot for more information.");
  #https://www.cisa.gov/uscert/ncas/current-activity/2022/06/22/cisa-releases-security-advisories-related-oticefall-insecure
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4901fbd6");
  script_set_attribute(attribute:"see_also", value:"https://www.cisa.gov/uscert/ics/advisories/icsa-22-172-02");
  script_set_attribute(attribute:"see_also", value:"https://www.forescout.com/research-labs/ot-icefall/");
  script_set_attribute(attribute:"solution", value:
"Refer to the vendor advisory.");

  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:toyota:toyoda");
  
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Tenable.ot");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_ot_api_integration.nasl");
  script_require_keys("Tenable.ot/Toyota");

  exit(0);
}

include('tenable_ot_cve_funcs.inc');

get_kb_item_or_exit('Tenable.ot/Toyota');

var asset = tenable_ot::assets::get(vendor:'Toyota');

# From CISA:
# PC10G-CPU Type=TCC-6353
# PC10GE Type=TCC-6464
# PC10P Type=TCC-6372
# PC10P-DP Type=TCC-6726
# PC10P-DP-IO Type=TCC-6752
# PC10B-P Type=TCC-6373
# PC10B Type=TCC-1021
# PC10E Type=TCC-4737
# PC10EL Type=TCC-4747
# Plus CPU Type=TCC-6740
# PC3JX Type=TCC-6901
# PC3JX-D Type=TCC-6902
# PC10PE Type=TCC-1101
# PC10PE-1616P Type=TCC-1102
# PCDL Type=TKC-6688
# Nano 10GX Type=TUC-1157
# Nano CPU Type=TUC-6941
# All versions. So, we'll add both model and type
# in case we get either in the modelName field.

var vuln_models = {
  'PC10G-CPU' : {},
  'PC10GE' : {},
  'PC10P' : {},
  'PC10P-DP' : {},
  'PC10P-DP-IO' : {},
  'PC10B-P' : {},
  'PC10B' : {},
  'PC10E' : {},
  'PC10EL' : {},
  'Plus CPU' : {},
  'PC3JX' : {},
  'PC3JX-D' : {},
  'PC10PE' : {},
  'PC10PE-1616P' : {},
  'PCDL' : {},
  'Nano 10GX' : {},
  'Nano CPU' : {},
  'TCC-6353' : {},
  'TCC-6464' : {},
  'TCC-6372' : {},
  'TCC-6726' : {},
  'TCC-6752' : {},
  'TCC-6373' : {},
  'TCC-1021' : {},
  'TCC-4737' : {},
  'TCC-4747' : {},
  'TCC-6740' : {},
  'TCC-6901' : {},
  'TCC-6902' : {},
  'TCC-1101' : {},
  'TCC-1102' : {},
  'TKC-6688' : {},
  'TUC-1157' : {},
  'TUC-6941' : {}
};

tenable_ot::cve::compare_and_report(asset:asset, vuln_models:vuln_models, severity:SECURITY_NOTE);
