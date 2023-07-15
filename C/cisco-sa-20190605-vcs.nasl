#TRUSTED 0cccacf0bde043b85d42c10063cffec01b0a8877fe130c2f1fa35f8eee9788318946afb6ae96899605dfb5355346839de107457d4ee7f161d316bb58aefbf0e33be8c6894353500c1d6eec85a6b94e6267278739013454b8d2e5be7875a89ed15827c3e1e1164e2f9fd957f2d455a1d56e5e88a5d9354acad1c7747f87e656788e78a720cfe369b66c7dd9763bf16060760b9fe1db2b7fed4bd7fb607764567328730bde8bb05465cfc28f33ff997086849dd27d7a0f754f964a9a01518b1591283cf00627e7037d3a79661e6851f09c65da10e5d69e49c466beac74aae06fed587a5df485ed939365f04a8775c533946e3d048776df7b59a29c8d5cfc8e4e51ed34757234c2cf8378e88b444130cfc206ce7d7515fdd04777246dcd1bd1c3c867c92831d7ee6df353de1aa42467271501527359f8d434fb9458c293558b79cf3d4402781d03288975169f8168a9556679557cb7b6ee28714a6a639dbf27a9865254f2ffa3216a7c97283a64ddcf6b323fbd5af1eb8b88105299d01926e7cd5869b90cc61e1a029026870f9f563bc68d3b35ade012d4754a5264b6de6565d556fa7b55900d141bfa11d4f152e367d4053fb769e1fdbca2adb606817225d0696714b24fb6701202251dd357a81e6da5860bfecb1b978acb01e5a6a85a8215082cad6993c70130452a133ae227093d8c0d029164f1a556a8c68dddc4af4516c6f8
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134227);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-1872");
  script_bugtraq_id(108677);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj33774");
  script_xref(name:"IAVA", value:"2019-A-0215-S");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190605-vcs");

  script_name(english:"Cisco TelePresence Video Communication Server and Cisco Expressway Series Server-Side Request Forgery Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The version of Cisco TelePresence Video Communication Server installed
on the remote host is affected by a SSRF vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Cisco
TelePresence Video Communication Server is affected by an input-
validation flaw that allows server-side request forgery (SSRF) leading
to arbitrary network requests from the affected device.");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj33774");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190605-vcs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81c51911");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 12.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1872");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco TelePresence VCS');

vuln_ranges = [{ 'min_ver':'0', 'fix_ver' : '12.5.0' }];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvj33774',
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
