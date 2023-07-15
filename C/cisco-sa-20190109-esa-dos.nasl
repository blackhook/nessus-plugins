#TRUSTED 7a4b09f9f822ac081b19b3f29739f82a12d09cd442323663760b5f5cf0a586551808f369c93e48194b8bc0507fd1445aae0e892b2da14a588fd0b9c88d46d3e84bb76e1e9f4d0190cc4fac58954eb76930eaba88962719c04d62542acc2caf075d8af2efd133b1b22bc0ef40c1c71aeb60a332635a977bd4d8c4c94fdea7a3145f094eeffed32e3b9a8cea0821700f7202a620445826f847b12f9df1a32908f76846f47af0517845f73dd0b819465fd5f7244af88d1b022863d9bdb06d311193c0296f572f39e17fa786738bf889f0a623d6ac4232014bab66e8d7fd7c9df420d246f12e7c0bc5c4d4d35fa7ba5bf803fef74d3bdb741645ad23d672d61c341b442170230fb9a4f00e990725ea8733872a673787709f47c48359d597c484a972531ea7f86cb0044d59e8797990ba82d755a30822cc405235c4a2ef5c7c8fb038c194fa42d4f8cce175fea2211411c68ff5f0081451e74c61da8ed3403655ccc34769374805d55efaef38386fff36531c6ae230c3d5c86ec9a86bd0c9c2f8594f30a3875e9aa46b42b75e8d8926cea4155a013a3791308cfe207aad85ddae560dc16fb5b7f5b25eb3ff1effbeac70df9a3f562d8b190cd4187161808d5e807a89a4ee588201297567acf95054b8e707132ead2c2ae56359ee2d3815e3980937f7b573429d198fd01285fd5c1b992d1074a535df7fbb30acac8902d68806759820
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121248);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id("CVE-2018-15453", "CVE-2018-15460");
  script_bugtraq_id(106507, 106511);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk73786");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm81627");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190109-esa-dos");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190109-esa-url-dos");

  script_name(english:"Cisco Email Security Appliance Multiple DoS Vulnerabilities (cisco-sa-20190109-esa-dos / cisco-sa-20190109-esa-url-dos)");
  script_summary(english:"Checks the Cisco Email Security Appliance (ESA) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Email Security
Appliance (ESA) is affected by the following vulnerabilities:

  - A denial of service (DoS) vulnerability exists in
    Secure/Multipurpose Internet Mail Extensions (S/MIME)
    Decryption and Verification and S/MIME Public Key
    Harvesting features due to improper input validation of
    S/MIME-signed emails. An unauthenticated, remote
    attacker can exploit this issue, via malicious
    S/MIME-signed email, to cause the process to stop
    responding. (CVE-2018-15453)

  - A denial of service (DoS) vulnerability exists in email
    message filtering feature due to improper filtering of
    email messages that contain references to whitelisted
    URLs. An unauthenticated, remote attacker can exploit
    this issue, via malicious email message that contains a
    large number of whitelisted URLs, to cause the system to
    stop responding (CVE-2018-15460).");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190109-esa-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17b6199e");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190109-esa-url-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3856e4d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk73786");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm81627");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security Advisory
cisco-sa-20190109-esa-dos and cisco-sa-20190109-esa-url-dos.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15453");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco Email Security Appliance (ESA)");

vuln_list = [
  {'min_ver' : '0', 'fix_ver' : '11.0.2.044'},
  {'min_ver' : '11.1.0.0', 'fix_ver' : '11.1.2.023'}
];

if(product_info['version'] =~ "^11\.1\.") fixed='11.1.2-023';
else fixed='11.0.2-044';

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version', product_info['display_version'],
  'fix', fixed
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_list);
