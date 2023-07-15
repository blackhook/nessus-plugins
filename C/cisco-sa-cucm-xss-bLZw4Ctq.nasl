#TRUSTED 966e520a471b49a3f6e3f3f063c9c14faa58d6851fa00365a65304d49b7f0b88153010c5832f1a63e6e4fa98e1d20e57b1a1d5f4837042fd726287eecf37bef5da0c0d36b03fcb3969507e887c57f6937595f3a2f3c876b617536ccaa6ca61d17385f3d15e2867b48023518a707766043d8974c2668d1f4743773f98820790e6bc0aa9031653445c05a408b93027661150d76da99b932a6b1aec120f2bebd4145c18201558bac5ca53f2e9a1cfe9145b7e7e6c835f34ba1cb1b7230864dab92f73a751033182ed5c96508547a257b73b047de36d4d792b3f12e26e961bd298cd63164993d876ba9944749f9af92084f746da3985fedec0221c4c3290b6efe2be139fd43ba3c2b06d95ba6b9d8761189b77c86e86ee4a1a5befd58f4d7857806d860793cc92932627398320e021680543c1b43db061b1785438e5f5c221bd3c14e98f0df55ee04922dc78c4a688afab488048ac9166a019c67f5e36b58d8c833edaedbfb73fd37f431616de9770bdfaf74827d367e566367ba37624278377f476f87c665a9c30e73cb8b0fa596823623ac74b0c9d6008ccba9cc6d01d2e7f400ceaf9bb53c9d6d6007914445c1de0dd0c1c9ea51a151ccd87886748c5c973b510b3b0138cebfc0eb2269fd25e7ab2f02294ffd7421ed17097696b0ebdddb6939dc08c1c8681564575a2021eceeb7ab3347e44dc714fd895eace958f4c64a53385
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138373);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-3420");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs88276");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-xss-bLZw4Ctq");
  script_xref(name:"IAVA", value:"2020-A-0297-S");

  script_name(english:"Cisco Unified Communications Manager Stored Cross-Site Scripting (cisco-sa-cucm-xss-bLZw4Ctq)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Communications Manager is affected by a Cross-Site Scripting
vulnerabilities. An attacker could exploit this vulnerability by inserting malicious data into a specific data field in
the web interface. A successful exploit could allow the attacker to execute arbitrary script code in the context of the
affected interface or access sensitive browser-based information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-xss-bLZw4Ctq
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a680bdf");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs88276");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs88276");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3420");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

# At the time of publication, this vulnerability affected all releases of Cisco Unified
# CM and Cisco Unified CM SME software. Bug ID mention release 12.5(1.10000.22) only.

version_list=make_list(
  '12.5.1.10000.22'
);

reporting = make_array(
  'port'     , 0,
  'version'  , product_info['version'],
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvs88276',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);