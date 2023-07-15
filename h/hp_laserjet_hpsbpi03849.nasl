#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, inc.
##

include('compat.inc');

if (description)
{
  script_id(177398);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id("CVE-2023-1329");
  script_xref(name:"HP", value:"HPSBPI03849");
  script_xref(name:"IAVA", value:"2023-A-0286");

  script_name(english:"HP LaserJet Printers RCE (HPSBPI03849)");

  script_set_attribute(attribute:"synopsis", value:
"The remote printer is affected by a buffer overflow / remote code execution 
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its model number and firmware revision, the remote HP
LaserJet printer is affected by a buffer overflow / remote code execution 
vulnerability.");
  # https://support.hp.com/us-en/document/ish_8585737-8585769-16/hpsbpi03849
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a404f117");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the HP LaserJet firmware referenced in the
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1329");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:laserjet");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_laserjet_detect.nasl");
  script_require_keys("www/hp_laserjet");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('http.inc');
include('vcf_extras.inc');

var app_info = vcf::hp_laserjet::get_app_info();

# If its not one of these models, its not affected.
# Models taken from advisory.
var affected_models = make_list(
  "B5L46A",
  "B5L47A",
  "B5L48A",
  "B5L54A",
  "B5L49A",
  "B5L50A",
  "7ZU85A",
  "7ZU86A",
  "7ZU87A",
  "7ZU88A",
  "J8A10A",
  "J8A11A",
  "J8A12A",
  "J8A13A",
  "J8A16A",
  "J8A17A",
  "T3U55A",
  "T3U56A",
  "3GY25A",
  "3GY26A",
  "L3U66A",
  "L3U67A",
  "L3U69A",
  "L3U70A",
  "3GY31A",
  "3GY32A",
  "5CM75A",
  "5CM76A",
  "5CM77A",
  "5CM78A",
  "5CM79A",
  "5RC91A",
  "5RC92A",
  "X3A77A",
  "X3A80A",
  "X3A83A",
  "Z8Z01A",
  "Z8Z0A",
  "Z8Z05A",
  "X3A78A",
  "X3A81A",
  "X3A84A",
  "Z8Z00A",
  "Z8Z02A",
  "Z8Z04A",
  "8GS12A",
  "8GS13A",
  "8GS14A",
  "8GS15A",
  "8GS36A",
  "8GS37A",
  "8GS43A",
  "8GS44A",
  "8GS50A",
  "17F27AW",
  "19GSAW",
  "8GS00A",
  "8GS01A",
  "8GS25A",
  "8GS26A",
  "8GS27A",
  "8GS28A",
  "8GS29A",
  "8GS30A",
  "8GR94A",
  "8GR95A",
  "8GR96A",
  "8GR97A",
  "8GR98A",
  "8GR99A",
  "8PE94A",
  "8PE95A",
  "8PE96A",
  "8PE97A",
  "8PE98A",
  "9RT91A",
  "9RT92A",
  "5QJ83A",
  "5QK15A",
  "5QJ81A",
  "X3A86A",
  "X3A87A",
  "X3A89A",
  "X3A90A",
  "X3A92A",
  "X3A93A",
  "Z8Z12A",
  "Z8Z13A",
  "Z8Z14A",
  "Z8Z15A",
  "Z8Z16A",
  "Z8Z17A",
  "5CM63A",
  "5CM64A",
  "5CM65A",
  "5CM66A",
  "5FM80A",
  "5FM81A",
  "5FM82A",
  "5RC86A",
  "5RC87A",
  "5RC88A",
  "5QK03A",
  "5QK08A",
  "5QK20A",
  "3SJ19A",
  "3SJ20A",
  "3SJ21A",
  "3SJ22A",
  "3SJ35A",
  "3SJ36A",
  "3SJ37A",
  "3SJ38A",
  "F2A76A",
  "F2A77A",
  "F2A78A",
  "F2A81A",
  "F2A79A",
  "F2A80A",
  "1PV49A",
  "1PV64A",
  "1PV65A",
  "1PV66A",
  "1PV67A",
  "J8J63A",
  "J8J64A",
  "J8J65A",
  "J8J70A",
  "J8J71A",
  "J8J72A",
  "J8J76A",
  "J8J78A",
  "7PS94A",
  "7PS95A",
  "7PS96A",
  "7PS97A",
  "7PS98A",
  "7PS99A",
  "7PT00A",
  "7PT01A",
  "3GY19A",
  "3GY20A",
  "1PS54A",
  "1PS55A",
  "J8J66A",
  "J8J67A",
  "J8J73A",
  "J8J74A",
  "J8J79A",
  "J8J80A",
  "3GY14A",
  "3GY15A",
  "3GY16A",
  "3GY17A",
  "3GY18A",
  "5CM68A",
  "5CM69A",
  "5CM70A",
  "5CM71A",
  "5CM72A",
  "5RC89A",
  "5RC90A",
  "X3A59A",
  "X3A60A",
  "X3A62A",
  "X3A63A",
  "X3A65A",
  "X3A66A",
  "Z8Z06A",
  "Z8Z07A",
  "Z8Z08A",
  "Z8Z09A",
  "Z8Z010A",
  "Z8Z011A",
  "5QJ87A",
  "3SJ03A",
  "3SJ04A",
  "5QJ98A",
  "5QK02A",
  "3SJ00A",
  "3SJ01A",
  "3SJ02A",
  "6BS57A",
  "6BS58A",
  "6BS59A",
  "X3A68A",
  "X3A69A",
  "X3A71A",
  "X3A72A",
  "X3A74A",
  "X3A75A",
  "X3A79A",
  "X3A82A",
  "Z8Z18A",
  "Z8Z19",
  "AZ8Z20A",
  "Z8Z22A",
  "Z8Z23A",
  "5CM59A",
  "5RC83A",
  "5FM76A",
  "5CM58A",
  "5RC84A",
  "5FM77A",
  "5CM61A",
  "5RC85A",
  "5FM78A",
  "5QK09A",
  "5QK13A",
  "3SJ07A",
  "3SJ08A",
  "3SJ09A",
  "3SJ28A",
  "3SJ29A",
  "3SJ30A",
  "G1W39A",
  "G1W40A",
  "G1W41A",
  "4PZ43A",
  "4PA44A",
  "4PZ45A",
  "4PZ46A",
  "J7Z11A",
  "J7Z12A",
  "J7Z09A",
  "J7Z10A",
  "L3U42A",
  "L3U43A",
  "J7Z13A",
  "Z5G79A",
  "J7Z08A",
  "J7Z14A",
  "J7Z05A",
  "Z5G77A",
  "J7Z03A",
  "J7Z07A",
  "Y3Z61A",
  "Y3Z62A",
  "Y3Z63A",
  "Y3Z64A",
  "Y3Z65A",
  "Y3Z66A",
  "Y3Z68A",
  "2GP22A",
  "2GP23A",
  "2GP25A",
  "2GP26A",
  "5ZN98A",
  "5ZN99A",
  "5ZP00A",
  "5ZP01A",
  "L2762A",
  "L2763A",
  "58R10A",
  "6QN31A",
  "6QN29A",
  "6QN30A",
  "49K96AV",
  "6QN35A",
  "6QN36A",
  "6QN37A",
  "6QN38A",
  "49K84A",
  "4Y279A",
  "6QP98A",
  "6QP99A",
  "49K97AV");

var constraints = [
  { 'models': affected_models, 'fixed_version': '5.6.0.2'}
];

vcf::hp_laserjet::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);