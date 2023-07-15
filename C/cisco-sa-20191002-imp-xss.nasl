##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(130398);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/10");

  script_cve_id("CVE-2019-12707");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq12061");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-cuc-xss");
  script_xref(name:"IAVA", value:"2019-A-0362");

  script_name(english:"Cisco Unified Communications Manager IM and Presence XSS (cisco-sa-20191002-cuc-xss)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A cross-site scripting (XSS) vulnerability exists due to improper validation of user-supplied input before returning it
to users. An unauthenticated, remote attacker can exploit this, by convincing a user to click a specially crafted URL, 
to execute arbitrary script code in a user's browser session.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-cuc-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5a7d927");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq12061");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq12061");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12707");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager_im_and_presence_service");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_presence_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_cucm_imp_detect.nbin");
  script_require_keys("installed_sw/Cisco Unified CM IM&P");

  exit(0);
}

include('vcf.inc');

app = 'Cisco Unified CM IM&P';
get_kb_item_or_exit('installed_sw/' + app);

app_info = vcf::get_app_info(app:app);

constraints = [
  # 11.5(1)SU6 https://www.cisco.com/web/software/282074312/145780/ReadMe_for_Cisco_Unified_IM_and_Presence_11.5.1SU6.pdf
  {'min_version' : '11.5', 'fixed_version' : '11.5.1.16910.12'},
  # 12.5(1)SU1 https://www.cisco.com/web/software/282074312/146821/ReadMe_for_Cisco_Unified_IM_and_Presence_12.5.1SU1.pdf
  {'min_version' : '12.5', 'fixed_version' : '12.5.1.11900.117'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
