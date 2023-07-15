#TRUSTED 34f624396ec6c0016a20d7eb808c6979d9675ffcf20bd5b7069cfcb9b4306ffa850c22afbcfb34ade95d1e6f5f2db5aa3a959ffe0b357aaab521ddf66d119d14fb6c90fcbb48e775cf5db5c8c358e5e976bf50e411a812f6e07dfcb9993b16baca36f038a5b849c702e7f43e85085433bfa326082c2e6d0a9c5f9c06193b698c726a67ea1c9adc16fb8b4f6014ef7e475e33d6f673f6e2d277f8d52de1c9e28482e0e8599bf24e417848c5c0eb9025d4c7087562f7ed487e170451969db38f11e00447d084ee79a6e50e05115a1663508b7204e194c431e46171cd4aab16f9c2757fc0b10d8fceaa15fea9a1fc77f91519928ca2f6c98f1e447bcc9a627977f374cc84231d608c05c3241fb8983ac403135894e5a235ee2b53a9e2e17934fd33cfdb98145fd340eac1f630bc66e341e635fd758cc4d734230653b7c3a5347855a1068c853fbb2b4ea00c75621ba31d65e0bdcf924771c6e970d62c63af69d5874d6fd47eb49d6e32db6d2c2775208a792291e4816b5950efe266576b1772c0f5696ad5cae6f40a92d9f8df996fd2e6630350b4f474c0ec82b334b8c14e15dc8af71d992db876338d303797f9da773794cf75a734149c54f724a23d568a4a4c8e9d328c917814e49181ef92b5b662dcea8569d66e2c6dc949cbafa2ffd3e2fae9206124d4239732a848de11250587ce08f3625bd08515e453bf7c1bf6569efd8d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129824);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2019-12706");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq35034");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-esa-bypass");
  script_xref(name:"IAVA", value:"2019-A-0368-S");

  script_name(english:"Cisco Email Security Appliance Filter Bypass Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance (ESA) is affected by a filter bypass
vulnerability in the Sender Policy Framework (SPF) functionality of Cisco AsyncOS Software for Cisco Email Security
Appliance (ESA) due to insufficiently validating certain incoming SPF messages. An unauthenticated, remote attacker
could exploit this, via vulnerability by sending a custom SPF packet, to bypass the configured header filters, which
could allow malicious content to pass through the device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-esa-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fbba4881");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq35034");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq35034");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12706");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_(esa)");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

vuln_ranges = [
  { 'min_ver' : '0', 'fix_ver' : '12.5.1.031' },
  { 'min_ver' : '13', 'fix_ver' : '13.0.0.375' }
];

reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvq35034',
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
