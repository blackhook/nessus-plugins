#TRUSTED a5220947364570a79ca883dbfe51ef5629addbd3a752e0fac8fb93916acc9cf45b67522f436d639a5e33665609f0aa84c1822733552f01cad3fdd7295f79b48d251e0f5bb43662f734b650d1b95c869efe8473dc6719605dd27254b881892bde16305457fb2c6e6c1a7440d82e1dbdc0d1628b8d9b4f4555a9321b174cf3de913e9c1993a6fb865f21895c4933750511419b6036b29f359d7658395c5cee3a444dd1847ca28bef32014f932416303d514e713bf57bc8546a90aa2968082b8b2b82b0c3dac52995611aaf4b38300584df0fcc1c48bfbe0a0c5a059b3b070ba54cbeb087fd03cc66d66b2e896499d4add3cc24b147120579b28d52a6ffee76814c0dd4d458f43df8932e4c7aee828cc2c9f464368f56684ccc30229258239d66399770345d68fa5564427264c60d2ab13df10ff08363febc3cc8b476cca968c291c0d75acf37c87813690d909f737fc118a45af5992e4f5ff0c01e780c47172413200eacde96d52c534a9bb6ee37cef18768a95081803e9a7f30369dee4d15c23b379ec385401c3be825a39015ccc592051e0f583e3f9df93f55243bb552c44d42eb65442dc98eeae1f0e3d71544b0fdcf6232e871a0c3d8713cce18e4e51805fb878484d1f11f8591e72bd78016dfefbdf6814b8b485c91a24b2c8c491869a68e4c6a634cdabaab5b33a9458b0ecc1779e5620349dc39cb00429350de6acf53ca
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152987);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/13");

  script_cve_id("CVE-2021-34732");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy43411");
  script_xref(name:"CISCO-SA", value:"cisco-sa-prime-collab-xss-fQMDE5GO");
  script_xref(name:"IAVA", value:"2021-A-0402");

  script_name(english:"Cisco Prime Collaboration Provisioning XSS (cisco-sa-prime-collab-xss-fQMDE5GO)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Prime Collaboration Provisioning is affected by a cross-site scripting 
(XSS) vulnerability in its web-based management interface due to improper validation of user-supplied input before 
returning it to users. An unauthenticated, remote attacker can exploit this, by convincing a user to click a specially
crafted URL, to execute arbitrary script code in a user's browser session.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-prime-collab-xss-fQMDE5GO
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3ea2c72");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy43411");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy43411");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34732");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_collaboration_provisioning");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_collaboration_provisioning_detect.nbin");
  script_require_keys("Host/Cisco/PrimeCollaborationProvisioning/version");

  exit(0);
}
include('vcf.inc');

var app = 'Prime Collaboration Provisioning';
var app_info = vcf::get_app_info(app:app, kb_ver:'Host/Cisco/PrimeCollaborationProvisioning/version');

# We got the version from the WebUI and its not granular enough
if (app_info['version'] == '12')
  audit(AUDIT_VER_NOT_GRANULAR, app, app_info['version']);

var constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '12.6.0.3493', 'fixed_display' : '12.6 SU3'}
]; 

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
