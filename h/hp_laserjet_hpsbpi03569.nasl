#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(104812);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/16");

  script_cve_id("CVE-2017-2750");
  script_xref(name:"HP", value:"HPSBPI03569");
  script_xref(name:"IAVB", value:"2017-B-0166-S");

  script_name(english:"HP LaserJet Printers RCE (HPSBPI03569)");

  script_set_attribute(attribute:"synopsis", value:
"The remote printer is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its model number and firmware revision, the remote HP
LaserJet printer is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://support.hp.com/gb-en/document/c05839270");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the HP LaserJet firmware referenced in the
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-2750");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:laserjet");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_laserjet_detect.nasl");
  script_require_keys("www/hp_laserjet");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('http.inc');

var port = get_http_port(default:80, dont_break:TRUE, embedded:TRUE);
                                                                           # Examples:
var product   = get_kb_item_or_exit('www/hp_laserjet/'+port+'/pname');         # HP LaserJet M750
var model     = get_kb_item_or_exit('www/hp_laserjet/'+port+'/modelnumber');   # D3L09A
var firmware  = get_kb_item_or_exit('www/hp_laserjet/'+port+'/fw_rev');        # 2304061_439474
var url       = get_kb_item_or_exit('www/hp_laserjet/'+port+'/url');
var fs_full   = get_kb_item('www/hp_laserjet/'+port+'/fw_bundle_ver'); # 3.9.8 or 4.1.2

var full_product = "HP LaserJet " + product + " Model " + model;

var parts = split(firmware, sep:"_", keep:FALSE);
var firmware_major = parts[0]; 
# Some models have different fixed fw versions depending on the futuresmart version
var fs_ver = split(fs_full, sep:".", keep:FALSE);
var fs = fs_ver[0];

var serial = get_kb_item('www/hp_laserjet/'+port+'/serial');
if (empty_or_null(serial)) serial = "unknown";

var vuln = FALSE;

if (isnull(fs_full)) audit(AUDIT_UNKNOWN_APP_VER, "FutureSmart");

if (fs < 4)
{ 
if (model == "CC419A" ||
    model == "CC420A" ||
    model == "CC421A" ||
    model == "CE707A" ||
    model == "CE708A" ||
    model == "CE709A" ||    
    model == "B5L23A" ||    
    model == "B5L24A" ||
    model == "B5L25A" ||
    model == "B5L26A" ||
    model == "CZ255A" ||
    model == "CZ256A" || 
    model == "CZ257A" || 
    model == "CZ258A" || 
    model == "D3L08A" ||
    model == "D3L09A" ||
    model == "D3L10A" ||
    model == "B5L46A" || 
    model == "B5L47A" || 
    model == "B5L48A" ||
    model == "B5L49A" ||
    model == "B5L50A" ||
    model == "B5L54A" ||
    model == "CZ250A" ||
    model == "CZ251A" ||
    model == "CZ248A" ||
    model == "CZ249A" ||
    model == "CD644A" ||
    model == "CD645A" ||
    model == "CF116A" ||
    model == "CF117A" ||
    model == "L3U59A" ||
    model == "L3U60A" ||        
    model == "CE989A" ||
    model == "CE990A" ||
    model == "CE991A" ||
    model == "CE992A" ||
    model == "CE993A" ||
    model == "CE994A" ||
    model == "CE995A" ||
    model == "CE996A" ||
    model == "CC522A" ||
    model == "CC523A" ||
    model == "CC524A" ||
    model == "CF235A" ||
    model == "CF236A" ||
    model == "CF238A" ||
    model == "A2W77A" ||
    model == "A2W78A" ||
    model == "A2W79A" ||
    model == "D7P73A" ||
    model == "A2W76A" ||
    model == "A2W75A" ||
    model == "D7P71V" ||
    model == "D7P71A" ||
    model == "D7P68A" ||
    model == "L3U51A" ||
    model == "L3U52A" ||
    model == "L3U65A" ||
    model == "CF081A" ||
    model == "CF082A" ||
    model == "CF083A" ||
    model == "CD646A" ||
    model == "CF367A" ||
    model == "CF118A" ||
    model == "B3G85A" ||
    model == "CE503A" ||
    model == "CE504A" ||
    model == "CE738A" ||
    model == "F2A68A" ||
    model == "F2A69A" ||
    model == "F2A70A" ||
    model == "F2A71A" ||
    model == "F2A76A" ||
    model == "F2A77A" ||
    model == "F2A81A" ||
    model == "E6B67A" ||
    model == "E6B68A" ||
    model == "E6B69A" ||
    model == "E6B70A" ||
    model == "E6B71A" ||
    model == "E6B72A" ||
    model == "E6B73A" ||
    model == "CZ244A" ||
    model == "CZ245A" ||
    model == "J7X28A" ||
    model == "B3G84A" ||
    model == "B3G86A" ||
    model == "CF066A" ||
    model == "CF067A" ||
    model == "CF068A" ||
    model == "CF069A" ||
    model == "B5L06A" ||
    model == "B5L06V" ||
    model == "B5L07A" ||
    model == "B5L04A" ||
    model == "B5L04V" ||
    model == "B5L05A" ||
    model == "B5L05V" ||
    model == "L3U40A" ||
    model == "L3U41A" ||
    model == "C2S11A" ||
    model == "C2S11V" ||
    model == "C2S12A" ||
    model == "C2S12V" ||
    model == "L1H45A" ||
    model == "G1W39A" ||
    model == "G1W39V" ||
    model == "G1W40A" ||
    model == "G1W40V" ||
    model == "G1W46A" ||
    model == "G1W46V" ||
    model == "G1W47A" ||
    model == "G1W47V" ||
    model == "L3U44A" ||
    model == "G1W41A" ||
    model == "G1W41V" ||
    model == "L3U43A" ||
    model == "L3U42A" ||
    model == "L2762A" ||
    model == "L2717A")
    {
      fix = "2308937";
      vuln = TRUE;
    }
}  

else if (model == "J7Z04A" ||
    model == "J7Z09A" ||
    model == "J7Z10A" ||
    model == "J7Z11A" ||
    model == "J7Z12A" ||
    model == "J7Z06A" ||
    model == "J7Z08A" ||
    model == "J7Z14A" ||
    model == "Z5G77A" ||
    model == "J7Z03A" ||
    model == "J7Z07A" ||
    model == "J7Z05A" ||
    model == "J7Z13A" ||
    model == "Z5G79A" ||
    model == "L2683A" ||
    model == "L2762A")
{
  fix = "2405087";
  vuln = TRUE;
}

else if (model == "CZ255A" || 
    model == "CZ256A" || 
    model == "CZ257A" || 
    model == "CZ258A" || 
    model == "B5L46A" || 
    model == "B5L47A" || 
    model == "B5L48A" ||
    model == "B5L49A" ||
    model == "B5L50A" ||
    model == "B5L54A" ||
    model == "CZ250A" ||
    model == "CZ251A" ||
    model == "CZ248A" ||
    model == "CZ249A" ||
    model == "CA251A" ||
    model == "CD644A" ||
    model == "CD645A" ||
    model == "CF116A" ||
    model == "CF117A" ||
    model == "L3U59A" ||
    model == "L3U60A" ||
    model == "CF304A" ||
    model == "CC524C" ||
    model == "L3U49A" ||
    model == "L3U50A" ||
    model == "A2W77A" ||
    model == "A2W78A" ||
    model == "A2W79A" ||
    model == "D7P73A" ||
    model == "A2W76A" ||
    model == "A2W75A" ||
    model == "D7P70A" ||
    model == "D7P71A" ||
    model == "D7P71V" ||
    model == "D7P68A" ||
    model == "L3U51A" ||
    model == "L3U52A" ||
    model == "L3U65A" ||
    model == "CD646A" ||
    model == "CF367A" ||
    model == "CF118A" ||
    model == "B3G85A" ||
    model == "J8J64A" ||
    model == "J8J72A" ||
    model == "J8J78A" ||
    model == "F2A76A" ||
    model == "F2A77A" ||
    model == "F2A81A" ||
    model == "CZ244A" ||
    model == "CZ245A" ||
    model == "J7X28A" ||
    model == "J8J63A" ||
    model == "J8J65A" ||
    model == "J8J70A" ||
    model == "J8J71A" ||
    model == "J8J76A" ||
    model == "CF066A" ||
    model == "CF067A" ||
    model == "CF068A" ||
    model == "CF069A" ||
    model == "J8J67A" ||
    model == "J8J74A" ||
    model == "J8J79A" ||
    model == "J8J80A" ||
    model == "J8J66A" ||
    model == "J8J73A" ||
    model == "L3U70A" ||
    model == "L3U66A" ||
    model == "J8A12A" ||
    model == "J8A13A" ||
    model == "J8A17A" ||
    model == "L3U43A" ||
    model == "L3U42A" ||
    model == "G1W41A" ||
    model == "G1W41V" ||
    model == "L3U44A" ||
    model == "G1W46A" ||
    model == "G1W46V" ||
    model == "G1W47A" ||
    model == "G1W47V" ||
    model == "G1W39A" ||
    model == "G1W39V" ||
    model == "G1W40A" ||
    model == "G1W40V" ||
    model == "B5L04A" ||
    model == "B5L04V" ||
    model == "B5L05A" ||
    model == "B5L05V" ||
    model == "L3U40A" ||
    model == "L3U41A" ||
    model == "B5L06A" ||
    model == "B5L06V" ||
    model == "B5L07A")
{
  fix = "2405129";
  vuln = TRUE;
}

else if (model == "J7Z98A" || 
    model == "J7Z99A" || 
    model == "J8A04A" || 
    model == "J8A05A" || 
    model == "J8A06A" ||
    model == "L3U55A" ||
    model == "L3U56A" ||
    model == "L3U57A" ||
    model == "K0Q14A" ||
    model == "K0Q15A" ||
    model == "K0Q17A" ||
    model == "K0Q18A" ||
    model == "M0P32A" ||
    model == "K0Q19A" ||
    model == "K0Q20A" ||
    model == "K0Q21A" ||
    model == "K0Q22A" ||
    model == "M0P33A" ||
    model == "M0P35A" ||
    model == "M0P36A" ||
    model == "M0P39A" ||
    model == "M0P40A")
{
  fix = "2405130";
  vuln = TRUE;
}

if (!vuln) audit(AUDIT_DEVICE_NOT_VULN, full_product);

# Check firmware revision
#  Only look at the first part of the firmware revision (e.g. 2307497 of 2307497_543950).
#  The last part of the firmware revision changes for each model

if (ver_compare(ver:firmware_major, fix:fix) == -1)
{
  report =
    '\n  Product           : ' + product +
    '\n  Model             : ' + model +
    '\n  Serial number     : ' + serial +
    '\n  Source URL        : ' + url +
    '\n  Installed version : ' + firmware +
    '\n  Fixed version     : ' + fix +
    '\n';

  security_report_v4(extra:report, port:port, severity:SECURITY_HOLE);
}
else audit(AUDIT_DEVICE_NOT_VULN, full_product, firmware);
