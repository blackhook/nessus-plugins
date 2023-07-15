#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169304);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/27");

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

  script_name(english:"Foxit PhantomPDF < 10.1.10 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PhantomPDF application (formally known as Phantom) installed on the remote Windows
host is prior to 10.1.10. It is, therefore affected by multiple vulnerabilities:

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

  - A use-after-free vulnerability exists in the JavaScript engine of Foxit Software's PDF Reader, version
    12.0.1.12430. A specially-crafted PDF document can trigger the reuse of previously freed memory via
    misusing Optional Content Group API, which can lead to arbitrary code execution. An attacker needs to
    trick the user into opening the malicious file to trigger this vulnerability. Exploitation is also
    possible if a user visits a specially-crafted, malicious site if the browser plugin extension is enabled.
    (CVE-2022-40129)

  - Addressed potential issues where the application could be exposed to Read Access Violation, Use-after-
    Free, or Out-of-Bounds Read vulnerability and crash when parsing certain U3D files, which could be
    exploited by attackers to execute remote code or disclose information. This occurs as the application
    accesses the array or iterator outside the bounds, or uses the wild pointer or object that has been freed
    without proper validation. (CVE-2022-43637, CVE-2022-43638, CVE-2022-43639, CVE-2022-43640,
    CVE-2022-43641) (CVE-2022-43637, CVE-2022-43638, CVE-2022-43639, CVE-2022-43640, CVE-2022-43641)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PhantomPDF version 10.1.10 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-40129");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_phantom_installed.nasl");
  script_require_keys("installed_sw/FoxitPhantomPDF", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'FoxitPhantomPDF', win_local:TRUE);

var constraints = [
  { 'max_version' : '10.1.9.37808', 'fixed_version' : '10.1.10' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
