#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(104813);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/29");

  script_cve_id("CVE-2017-2750");
  script_xref(name:"HP", value:"HPSBPI03569");
  script_xref(name:"IAVB", value:"2017-B-0166-S");

  script_name(english:"HP OfficeJet Printers RCE (HPSBPI03569)");

  script_set_attribute(attribute:"synopsis", value:
"The remote printer is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its model number and firmware revision, the remote HP
OfficeJet printer is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://support.hp.com/gb-en/document/c05839270");
  script_set_attribute(attribute:"solution", value:
"Upgrade the HP OfficeJet firmware in accordance with the vendor
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
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:officejet");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_officejet_web_detect.nbin");
  script_require_keys("hp/officejet/detected");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, dont_break:TRUE);
                                                                       # Examples :
product   = get_kb_item_or_exit('hp/officejet/' + port + '/product');  # HP Officejet X555
model     = get_kb_item_or_exit('hp/officejet/' + port + '/model');    # C2S11A
firmware  = get_kb_item_or_exit('hp/officejet/' + port + '/firmware'); # 2302908_435004

full_product = "HP OfficeJet " + product + " Model " + model;

parts = split(firmware, sep:"_", keep:FALSE);
firmware_major = parts[0]; 

serial = get_kb_item('hp/officejet/serial');
if (empty_or_null(serial)) serial = "unknown";

affected_models =
  make_list(
    "B5L06A", "B5L06V", "B5L07A",          # Color Flow MFP X585
    "B5L04A", "B5L04V", "B5L05A", "B5L05V" # Color MFP X585
);

vuln = FALSE;
# Check model
foreach affected_model (affected_models)
{
  if (affected_model == model)
  {
    vuln = TRUE;
    break;
  }
}

if (!vuln) audit(AUDIT_DEVICE_NOT_VULN, full_product);

# Check firmware revision
#  Only look at the first part of the firmware revision (e.g. 2307497 of 2307497_543950).
#  The last part of the firmware revision changes for each model

fix = "2405129";

if (ver_compare(ver:firmware_major, fix:fix) == -1)
{
  report =
    '\n  Product           : ' + product +
    '\n  Model             : ' + model +
    '\n  Serial number     : ' + serial +
    '\n  Installed version : ' + firmware +
    '\n  Fixed version     : 2405129_000050' +
    '\n';

  security_report_v4(extra:report, port:port, severity:SECURITY_HOLE);
}
else audit(AUDIT_DEVICE_NOT_VULN, full_product, firmware);
