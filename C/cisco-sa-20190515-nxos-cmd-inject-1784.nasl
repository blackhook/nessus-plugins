#TRUSTED 5a13bac7638dee37b9c23c1a7effa8978554cb268d2a5a2664291910485f04b1ed4b29e50a2f95a6bfc4f952cb35541b95664991626fb9df256312843119422e253ca40de6c299cca4d0b957a608aabb4f57b8a8e3884699223a3e6b1bf10356125c47453c570bc43d25e3296e64651df99e93ea15559f8eed33800c3367a0fcac37ca148655bf6ff7928d935c5ec9a23c357fc80e717d0ef52282f97f0477d3022e504d7f88924e829701143b9a17cc3dc5aa6b29ab9f31660644ef0d4d9ee42aba17948c46a0d166d2acb7ab63100c06c327e2e83671157ab5e31bdf79de581994117b17af38a4369efe235e461adcdef0f8394eb4ff39013c1ba01fc7bc86f44618f45a88cb0508aabf7ae1d095a000f4a83427b53a82c5b2b6af3d55c5df010de4a6c6e89ced0960f087d37e2a874a3121c7c543c492159aeedc61af24ae9efa0226bb2280cb5525dd3c1b9744e439c0360b92c6a6c56fdd382a8f67452a6b3042b4f036851834fad814fedfb727d71e478df444d5cacc31330bbb1c263429fafc022a4eecc74cbd450d0dfa8d557c54b9a3910d7adcade00a209ad95b122cbdd5a75e4d2025c444e531f0410282f0906e0d70619faadae9784d2eb65e9c4a3f16cadabc75bf8090089d4431ffabd2dc59611fef320c4a4fc33a733a229dbfd374c7ea52d07822b8ab4e6a6b7572bfe52457df850449b80c778a7e84da04
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130768);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/25");

  script_cve_id("CVE-2019-1784");
  script_bugtraq_id(108369);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi42292");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj12273");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj12274");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-cmd-inject-1784");

  script_name(english:"Cisco NX-OS Software Command Injection (CVE-2019-1784)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a command injection vulnerability due to
insufficient validation of arguments passed to a specific CLI command on an affected device. An unauthenticated, local
attacker can exploit this to execute arbitrary commands on the underlying Linux operating system with elevated
privileges.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-cmd-inject-1784
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7eb8d386");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi42292");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj12273");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj12274");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvi42292, CSCvj12273, and CSCvj12274.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1784");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

# Not checking for digits after the leading numbers because software download page has, e.g., Nexus 56128P, and it
# seems like this should be included
if ('Nexus' >< product_info['device'] &&
    ( product_info.model =~ '^5[56][0-9]{2}' ||
      product_info.model =~ '^60[0-9]{2}' ))
  cbi = 'CSCvj12273';
else if ('Nexus' >< product_info['device'] && product_info.model =~ '^7[07][0-9]{2}')
  cbi = 'CSCvi42292';
else if (('UCS' >< product_info['device']) && (product_info['model'] =~ '^6[23][0-9][0-9]'))
  cbi = 'CSCvj12274';
else
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '7.3(0.2)',
  '7.3(0)D1(1)',
  '7.3(0)DX(1)',
  '7.3(0)DY(1)',
  '7.3(0)N1(1)',
  '7.3(0)N1(1b)',
  '7.3(0)N1(1a)',
  '7.3(1)D1(1B)',
  '7.3(1)D1(1)',
  '7.3(1)DY(1)',
  '7.3(1)N1(0.1)',
  '7.3(1)N1(1)',
  '7.3(2)D1(1A)',
  '7.3(2)D1(1)',
  '7.3(2)D1(2)',
  '7.3(2)D1(3)',
  '7.3(2)D1(3a)',
  '7.3(2)N1(0.296)',
  '7.3(2)N1(1)',
  '7.3(3)N1(1)',
  '8.2(1)',
  '8.2(2)',
  '7.3(4)N1(1)'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , cbi,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
