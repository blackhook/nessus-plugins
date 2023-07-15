##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147145);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2021-22883", "CVE-2021-22884", "CVE-2021-23840");
  script_xref(name:"IAVB", value:"2021-B-0012-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Node.js 10.x < 10.24.0 / 12.x < 12.21.0 / 14.x < 14.16.0 / 15.x < 15.10.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"Node.js - JavaScript run-time environment is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Node.js installed on the remote host is 10.x prior to 10.24.0, 12.x prior to 12.21.0, 14.x prior to
14.16.0, or 15.x prior to 15.10.0. It is, therefore, affected by multiple vulnerabilities as referenced in the
february-2021-security-releases advisory.

  - Node.js versions before 10.24.0, 12.21.0, 14.16.0, 15.10.0 are vulnerable to denial of service attacks when 
    too many connection attempts with an 'unknownProtocol' are established. This leads to a leak of file descriptors. 
    If the file descriptors limit is configured maliciously then this could result in the server not accepting new 
    connections or being able to open new files. If no file descriptor limit is configured, this can lead to 
    an excessive memory usage and cause the system to run out of memory. (CVE-2021-22883)

  - Node.js versions before 10.24.0, 12.21.0, 14.16.0, 15.10.0 are vulnerable to a DNS rebinding attack when the 
    whitelist includes “localhost6”. When “localhost6” is not present in /etc/hosts, it is just an ordinary domain that 
    is resolved via DNS over network. If the attacker controls the victim's DNS server or can spoof its responses, the 
    DNS rebinding protection can be bypassed by using the “localhost6” domain. As long as the attacker uses the 
    “localhost6” domain, they can still apply the attack described in CVE-2018-7160. (CVE-2021-22884)

  - Node.js versions before 10.24.0, 12.21.0, 14.16.0, 15.10.0 calls to EVP_CipherUpdate, EVP_EncryptUpdate and 
    EVP_DecryptUpdate may overflow the output length argument in some cases where the input length is close to the
    maximum permissable length for an integer on the platform. In such cases the return value from the function call 
    will be 1 (indicating success), but the output length value will be negative. This could cause applications to 
    behave incorrectly or crash. (CVE-2021-23840)  

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://nodejs.org/en/blog/vulnerability/february-2021-security-releases/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5bac8db3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Node.js version 10.24.0 / 12.21.0 / 14.16.0 / 15.10.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22884");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nodejs:node.js");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_nodejs_installed.nbin", "nodejs_win_installed.nbin");
  script_require_keys("installed_sw/Node.js");

  exit(0);
}

include('vcf.inc');

win_local = FALSE;
if (get_kb_item('SMB/Registry/Enumerated')) win_local = TRUE;

app_info = vcf::get_app_info(app:'Node.js', win_local:win_local);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '10.0.0', 'fixed_version' : '10.24.0' },
  { 'min_version' : '12.0.0', 'fixed_version' : '12.21.0' },
  { 'min_version' : '14.0.0', 'fixed_version' : '14.16.0' },
  { 'min_version' : '15.0.0', 'fixed_version' : '15.10.0' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
