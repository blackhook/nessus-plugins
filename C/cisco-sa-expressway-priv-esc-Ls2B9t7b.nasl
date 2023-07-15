#TRUSTED 02c2eea920a70e9c1169e9844fcddac13c4ce6e028b534c24474d04655344f549c506ba850f5c91c3bae8fec2528ec95b9454b7af384a42c2ff4641c0b9acbaf5a1ffa3b56c02f8b29b60b01812999a1cac5a11367bd43ae2f4bd8c00be723077c8be5c660ac04b360698da75b640530ad2de816668453bd74793ed60a2d4bdb39ac2f54e36b9a1a5827f955311b2c61f1ecffe58994b8282f901539364f586241ad26f408f24d650a6b88167f0d86f926b443b84c9ef5b902bef69bb09f7d658018e827e1a023ad390e170c99c1874f3c3ccec1b461f9fd9cf2697b35f41beab373158cabad7563e31a06cc48f36f0c1bbb269d3bb45606106fc78db2c27a3f3bd23c68fc436802e93c56e1503bdd18cfdf50b21776ec8f94dc85a7bf9cb7e1746f709d66e0fdb0d9b21d3aaa4de2183ac77d328d27033c137381f66d902cfeac6cd2185a5045f56947c5bb2b33792a47cb73de808f3ef606fc2c1b5d6e0a272f7552c21b63cefcc556f8136691833afebd369121dca986a0323139a76413efd9988e9d8a360cdf7e18ac01d4d50466c7c9fd31b5ce0471de3a0226ba14c684653e6c28a9bdaf96a90386a045eb5767bcea807f76c9e821042d97ab2c0c2bf62bef666134500e9162ba693b96d851b9f34e2deccaa8398c1e7141913f806c45542d8055804864e91aa72a85fcce592c79df53214b251ac20e2ca0b45d406fa9
#TRUST-RSA-SHA256 645eb74f9be606d413a4cecda17431b0d00a3b3bf1656abea9080352c2e71ab797fc73e84ce86a37612939dc2ddfdd28dae810b0dcc8ccd0c64220dc41e317744a5b20877a6fca9ef233c04f1b259e779244497e54fadf22e8c34da7eb3e8c402944aa07fae3df3b5bba484ce50742c58333e75fae9ef1addeeb47f856e6853dd623c0f8eb17a736290c988512e1f2b7f97758e038e80f89707da5796fba74b8bfc9d30e93ca2b173370ec4433e27879823a42a5be6251f48c29d1b94cb638ac34cee69758d5339b7e51cc5542c6254b199089f4d47f7c8011d709444afea25835089dc93231b852de860abb06b308785be69cd9076c8dc61af12ad36e5c79282b3cf73bb658dd27e78a767962ca40d665334cfc4fa83bee8355b5a5e394a6f6c4a5450c46087d804590ea03574c288b4eb12ac3126a79ee4dab80eb8889f06956a721cd7bf2a62781128d81829dca2ab462311f08511198fc9380f3d2ae2896d211e7b3cd1b6e0c8acf3e9d17091ae76c1ab2675077e76877bd0ff4dc32cb4de4bcc5b0c7c77399f8348a2cb5c58b1e4518c0aa76e5107ddf647acc24c38047f4eeb8d792779176dd4a9858c08f68487ff2e84593a583d24c084dc869aeb6f9b9c0500539a8adbfb9f1d0e7dbcf84e94a1842db6313116b016cc2b0912e6eee62ead2f43abc5789cb5855dfceb6c801d52e6e8bfc60b99b0240e3aca7026e1c
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177367);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2023-20105");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz54058");
  script_xref(name:"CISCO-SA", value:"cisco-sa-expressway-priv-esc-Ls2B9t7b");
  script_xref(name:"IAVA", value:"2023-A-0282");

  script_name(english:"Cisco Expressway Series / Cisco TelePresence VCS < 14.2.1 Privilege Escalation (cisco-sa-expressway-priv-esc-Ls2B9t7b)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The Cisco Expressway Series or Cisco TelePresence Video Communication Server (VCS) running on the remote host is
prior to 14.2.1. It is, therefore, affected by a privilege escalation vulnerability as described in the
cisco-sa-expressway-priv-esc-Ls2B9t7b advisory. Due to incorrect handling of password change requests, a remote
attacker with read-only administrator privileges can alter the passwords of any user on the system, including those
with administrator read-write access.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-expressway-priv-esc-Ls2B9t7b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b350287");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz54058");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz54058");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20105");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco TelePresence VCS');

var vuln_ranges = [{ 'min_ver':'0.0', 'fix_ver' : '14.2.1' }];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvz54058',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
