#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(76129);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value: "2020/02/10");

  script_cve_id("CVE-2014-0076", "CVE-2014-0224", "CVE-2014-3470");
  script_bugtraq_id(66363, 67898, 67899);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup22590");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup23913");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140605-openssl");
  script_xref(name:"CERT", value:"978508");

  script_name(english:"Cisco Windows Jabber Client Multiple Vulnerabilities in OpenSSL (cisco-sa-20140605-openssl)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of Cisco Jabber installed that is known to be affected by multiple OpenSSL
related vulnerabilities :

  - An error exists related to the implementation of the Elliptic Curve Digital Signature Algorithm (ECDSA)
    that could allow nonce disclosure via the 'FLUSH+RELOAD' cache side-channel attack. (CVE-2014-0076)

  - An unspecified error exists that could allow an attacker to cause usage of weak keying material leading to
    simplified man-in-the-middle attacks. (CVE-2014-0224)

  - An unspecified error exists related to anonymous ECDH ciphersuites that could allow denial of service
    attacks. Note this issue only affects OpenSSL TLS clients. (CVE-2014-3470)");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCup23913 
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5114adab");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140605-openssl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5539aa9d");
  # https://www.openssl.org/news/secadv/20140605.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6039d37");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCup22590, CSCup23913");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0224");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:jabber");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_jabber_client_installed.nbin");
  script_require_keys("SMB/Cisco Jabber for Windows/Installed");

  exit(0);
}

include('audit.inc');
include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Cisco Jabber for Windows', win_local:TRUE);

constraints = [
  { 'min_version' : '9.0.0', 'max_version' : '9.0.6', 'fixed_display' : '9.7(3.18956), 9.7(4.18971), 10.5(0.36369) or later'},
  { 'min_version' : '9.1.0', 'max_version' : '9.1.5', 'fixed_display' : '9.7(3.18956), 9.7(4.18971), 10.5(0.36369) or later'},
  { 'min_version' : '9.2.0', 'max_version' : '9.2.6', 'fixed_display' : '9.7(3.18956), 9.7(4.18971), 10.5(0.36369) or later'},
  { 'min_version' : '9.6.0', 'max_version' : '9.6.1', 'fixed_display' : '9.7(3.18956), 9.7(4.18971), 10.5(0.36369) or later'},
  { 'min_version' : '9.7.0', 'max_version' : '9.7.2', 'fixed_display' : '9.7(3.18956), 9.7(4.18971), 10.5(0.36369) or later'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
