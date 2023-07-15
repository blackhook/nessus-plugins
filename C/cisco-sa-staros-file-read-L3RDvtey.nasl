#TRUSTED 7bb546521709d7f7ffc450f5576ceef3ff7ca663307b173101afa8e6f21c107e97f74e8c4d30bd185e8057505b588a4980eb4f79835be9a2d249ee6fd21b95eea12abe87b7c27d82ee64b2e4da2b2412dd33a33ac63419029fd228ae51288910fbcc67ed921ae6b476c0c1902c4761e3a8940fd18062af20f48096f446041a07dd99acae7a671491397435042e973ff22574d8c099e4815d4d901bc50e553eb1da1f32b86f435a28e6ec7d516c2bf51707de5c927c860c191309332ad26b26c237183ac5e8c6a2167ce4a72eeb51050b7600466647286f9c5dfbd6b84c3bcb5b3889eb5d4b006037f78242f3d992d007f844d2e672f170b752a5d99c8bd06e36d171aedfd8ffc462f6b8bf42c19f7a848f7d1271f04c06bb5c3f6cab121dae7cc960178edf92d8bedb0373c78b06ea951d189b77227a08c1514404cb2198e9ce99ac49caf979369d3d95e57f34f3f90d025ff586b923ff17e7f842c7c6d97a96ef4438d9e35aa5cdc70a5972b21977cb6745b1b4d6cc8af3288b996cc0c56d2407b5907664b851b1e92571702bc8c8c24567f94945e6fd8a2bc9bbcc92d291a7e0b8a2f6d5ba5bb3e70a31cd3192bc2f64cd1f3fdbab6e18476d6f3263b60dff412cb8014120e8fbbb3a403b5e6a5fb06d2617cb9ce04907cac37a32f5f6aa43eadfa3c9d2831a9bb52fc72369d94b420efaa392631542f19e5f332ef614832b
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145265);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2021-1145");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv34230");
  script_xref(name:"CISCO-SA", value:"cisco-sa-staros-file-read-L3RDvtey");
  script_xref(name:"IAVA", value:"2021-A-0029-S");

  script_name(english:"Cisco StarOS for Cisco ASR 5000 Series Routers Arbitrary File Read (cisco-sa-staros-file-read-L3RDvtey)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-staros-file-read-L3RDvtey)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco StarOS operating system on the remote Cisco ASR 5000 series router
is affected by an arbitrary file read vulnerability due to insecure handling of symbolic links. An authenticated, remote
attacker can exploit this, by sending a crafted SFTP command, to read arbitrary files on the affected device.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-staros-file-read-L3RDvtey
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a818821");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv34230");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv34230");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1145");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(61);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asr_5000_series");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASR/Model", "Host/Cisco/StarOS", "Host/Cisco/StarOS/Version");

  exit(0);
}

include('cisco_func.inc');

get_kb_item_or_exit('Host/Cisco/StarOS');

version = get_kb_item_or_exit('Host/Cisco/StarOS/Version');
model = get_kb_item_or_exit('Host/Cisco/ASR/Model');

# only affects ASR 5000 series systems
if (model !~ "^50\d{2}$")
  audit(AUDIT_DEVICE_NOT_VULN, 'The ASR ' + model);

fix = '21.19.7';

if (ver_compare(strict:FALSE, ver:version, fix:fix) < 0)
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    version  : version,
    fix      : fix,
    bug_id   : 'CSCvv34230'
  );
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco StarOS', version);
