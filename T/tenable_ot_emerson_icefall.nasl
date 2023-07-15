#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(500658);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/18");

  script_cve_id("CVE-2022-30261",
                "CVE-2022-30266",
                "CVE-2022-30263",
                "CVE-2022-29962",
                "CVE-2022-29963",
                "CVE-2022-29964",
                "CVE-2022-29965");   

  script_name(english:"Emerson OT:ICEFALL Multiple Potential Vulnerabilities");

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
  script_set_attribute(attribute:"see_also", value:"https://www.forescout.com/research-labs/ot-icefall/");
  script_set_attribute(attribute:"solution", value:
"Refer to the vendor advisory.");

  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:emerson:ovation_ocr1100");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:emerson:ovation_occ100");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:emerson:ovation_ocr400");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:emerson:roc_300");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:emerson:roc_800");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:emerson:dl_8000");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:emerson:pacsystems_rx7i");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:emerson:pacsystems_rx3i");
  
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Tenable.ot");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_ot_api_integration.nasl");
  script_require_keys("Tenable.ot/Emerson");

  exit(0);
}

include('tenable_ot_cve_funcs.inc');

get_kb_item_or_exit('Tenable.ot/Emerson');

var asset = tenable_ot::assets::get(vendor:'Emerson');

var vuln_cpes = {
    "cpe:/h:emerson:ovation_ocr1100" :
        {"family" : "Ovation"},
    "cpe:/h:emerson:ovation_occ100" :
        {"family" : "Ovation"},
    "cpe:/h:emerson:ovation_ocr400" : {},
    "cpe:/h:emerson:roc_300" :
        {"family" : "ROC300"},
    "cpe:/h:emerson:roc_800" :
        {"family" : "ROC800"},
    "cpe:/h:emerson:dl_8000" :
        {"family" : "ROC800"},
    "cpe:/h:emerson:pacsystems_rx7i" : {},
    "cpe:/h:emerson:pacsystems_rx3i" : {},
    "cpe:/h:emerson:deltav" : {}
};

tenable_ot::cve::compare_and_report(asset:asset, cpes:vuln_cpes, severity:SECURITY_NOTE);
