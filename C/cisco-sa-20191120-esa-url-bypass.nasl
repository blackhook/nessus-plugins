#TRUSTED 9f9e7e027180c7ff51b9936716fd92abf23e33deb960458eb2cc793e50a41610b7819bee157ae4f9c2ae12492a57332fa8821d20ae63a90f1300cbc10127d6093ee7281c6c610b98bf68b300d1a0e077972bd34ae245a20da31bf90b492073a233e4ed840859a3952167a302aa0a6746032a1c370631f3f9e1813b7efa19106181b8721729cb531dd55970ed2d92e3ceb6be0f3452261ed4e12f39d64d0980047677176dbe6ccaf4ee6c8af1c5fe9a8d075b4c8e7a1c299feb84371893a61e79ee41cd4a1b08e4fd7c2090d5cf732d6a9882fb52daf2ef5e5d5ccd80049677bddf8be978de4a420a6ba6db3fb0f64cc1a284955dace8090d8ed19e71d8950c783b8b72f3d003dbde9505779546ae3ad50fc5dfa397e065536626a1247b7f41a049d9b3d801fe0629c21cc14166cbfd2d4feaf7172b255dbd348bfc914b7462f9b7ff0d04af11903e32ca466f9801b9a766419d7a0273acdb0d6896813be5b7acc6e2cb1329ef3d57449d51824765d904014579f9be98f8fead15dcefb534f4c71cba6cf06d44aa0fb6ff999867ac2a09f94705817012888d90dff0ea32f88de9e3b858b1cd8ea958717701c8e6a893ad4c42ad2ac58ba1b1021edfda2a7caf0dfbe3c73fe7eebfec9d516325df537a4762b1f0f1f0d5afdf04b0644060730b1352a9d1e11705e21c709e830d83745b3c6679947a6ae9b50e3a9d1ce8535f576f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135289);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2019-15988");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq09347");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191120-esa-url-bypass");
  script_xref(name:"IAVA", value:"2019-A-0368-S");

  script_name(english:"Cisco Email Security Appliance URL Filtering Bypass (cisco-sa-20191120-esa-url-bypass)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance (ESA) is affected by a vulnerability in the
antispam protection mechanisms of Cisco AsyncOS Software due to insufficient input validation of URLs. An
unauthenticated, remote attacker can exploit this, by crafting the URL in a particular way, in order to bypass the URL
reputation filters on an affected device.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191120-esa-url-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?234ef0f1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq09347");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq09347");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15988");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_(esa)");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

vuln_ranges = [ { 'min_ver' : '0.0' , 'fix_ver' : '12.5.1' } ];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq09347'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
