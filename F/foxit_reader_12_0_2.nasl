#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167076);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/11");

  script_cve_id(
    "CVE-2022-32774",
    "CVE-2022-37332",
    "CVE-2022-38097",
    "CVE-2022-40129",
    "CVE-2022-43637",
    "CVE-2022-43638",
    "CVE-2022-43639",
    "CVE-2022-43640",
    "CVE-2022-43641"
  );
  script_xref(name:"IAVA", value:"2022-A-0485-S");

  script_name(english:"Foxit PDF Reader < 12.0.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PDF Reader application (previously named Foxit Reader) installed on the remote
Windows host is prior to 12.0.2. It is, therefore affected by multiple vulnerabilities:

  - A use-after-free vulnerability exists in the JavaScript engine of Foxit Software's PDF Reader, version
    12.0.1.12430. A specially-crafted PDF document can trigger the reuse of previously freed memory via
    misusing Optional Content Group API, which can lead to arbitrary code execution. An attacker needs to
    trick the user into opening the malicious file to trigger this vulnerability. Exploitation is also
    possible if a user visits a specially-crafted, malicious site if the browser plugin extension is enabled.
    (CVE-2022-40129)

  - A use-after-free vulnerability exists in the JavaScript engine of Foxit Software's PDF Reader, version
    12.0.1.12430. By prematurely deleting objects associated with pages, a specially-crafted PDF document can
    trigger the reuse of previously freed memory, which can lead to arbitrary code execution. An attacker
    needs to trick the user into opening the malicious file to trigger this vulnerability. Exploitation is
    also possible if a user visits a specially-crafted, malicious site if the browser plugin extension is
    enabled. (CVE-2022-32774)

  - A use-after-free vulnerability exists in the JavaScript engine of Foxit Software's PDF Reader, version
    12.0.1.12430. A specially-crafted PDF document can trigger the reuse of previously freed memory via
    misusing media player API, which can lead to arbitrary code execution. An attacker needs to trick the user
    into opening the malicious file to trigger this vulnerability. Exploitation is also possible if a user
    visits a specially-crafted, malicious site if the browser plugin extension is enabled. (CVE-2022-37332)

  - A use-after-free vulnerability exists in the JavaScript engine of Foxit Software's PDF Reader, version
    12.0.1.12430. By prematurely destroying annotation objects, a specially-crafted PDF document can trigger
    the reuse of previously freed memory, which can lead to arbitrary code execution. An attacker needs to
    trick the user into opening the malicious file to trigger this vulnerability. Exploitation is also
    possible if a user visits a specially-crafted, malicious site if the browser plugin extension is enabled.
    (CVE-2022-38097)

  - This vulnerability allows remote attackers to execute arbitrary code on affected installations of Foxit
    PDF Reader 12.0.1.12430. User interaction is required to exploit this vulnerability in that the target
    must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of U3D
    files. The issue results from the lack of validating the existence of an object prior to performing
    operations on the object. An attacker can leverage this vulnerability to execute code in the context of
    the current process. Was ZDI-CAN-18626. (CVE-2022-43637)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PDF Reader version 12.0.2 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-40129");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_reader_installed.nasl");
  script_require_keys("installed_sw/Foxit Reader", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Foxit Reader', win_local:TRUE);

var constraints = [
  { 'max_version' : '12.0.1.12430', 'fixed_version' : '12.0.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
