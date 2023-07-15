#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(161701);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_cve_id(
    "CVE-2021-21419",
    "CVE-2021-33503",
    "CVE-2022-23657",
    "CVE-2022-23658",
    "CVE-2022-23659",
    "CVE-2022-23660",
    "CVE-2022-23661",
    "CVE-2022-23662",
    "CVE-2022-23663",
    "CVE-2022-23664",
    "CVE-2022-23665",
    "CVE-2022-23666",
    "CVE-2022-23667",
    "CVE-2022-23668",
    "CVE-2022-23669",
    "CVE-2022-23670",
    "CVE-2022-23671",
    "CVE-2022-23672",
    "CVE-2022-23673",
    "CVE-2022-23674",
    "CVE-2022-23675"
  );

  script_name(english:"Aruba ClearPass Policy Manager <= 6.x.x < 6.8.9-HF2 / 6.9.x < 6.9.9 / 6.10.x < 6.10.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Aruba ClearPass Policy Manager installed on the remote host is prior or equal to 6.7, 6.8.9-HF2, 6.9.9, 6.10.4. It is, therefore,
affected by multiple vulnerabilities as referenced in the ARUBA-PSA-2022-007 advisory.

    - An information disclosure vulnerability exists in the web-based management interface of ClearPass Policy Manager.
    An authenticated, remote attacker can exploit this to disclose potentially sensitive information. (CVE-2022-23670)

    - A denial of service (DoS) vulnerability exists in the Python Eventlet library used by ClearPass Policy Manager. An
    unauthenticated, remote attacker can exploit this issue, via WebSocket peer to exhaust memory reserved by Eventlet
    inside of ClearPass Policy Manager, to cause the process to stop responding. (CVE-2021-21419)

    - A denial of service (DoS) vulnerability exists in Python Urllib library used by ClearPass Policy Manager. An
    authenticated, remote attacker can exploit this issue, via the web-based management, to cause the application to
    stop responding. (CVE-2021-33503)

    - An authentication bypass vulnerability exists in web-based management interface of ClearPass Policy Manager. An
    unauthenticated, remote attacker can exploit this to bypass authentication and execute arbitrary actions with root
    privileges. (CVE-2022-23657, CVE-2022-23658, CVE-2022-23660)

    - A reflected cross-site scripting (XSS) vulnerability exists in the web-based management interface of ClearPass
    Policy Manager due to improper validation of user-supplied input before returning it to users. An authenticated,
    remote attacker can exploit this, by convincing a user to click a specially crafted URL, to execute arbitrary script
    code in a user's browser session. (CVE-2022-23659)

    - A command injection vulnerability exists in the ClearPass Policy Manager command line interface. An authenticated,
    remote attacker can exploit this to execute arbitrary commands. (CVE-2022-23661, CVE-2022-23662)

    - A command injection vulnerability exists in the ClearPass Policy Manager web-based management interface. An
    authenticated, remote attacker can exploit this to execute arbitrary commands. (CVE-2022-23663, CVE-2022-23664,
    CVE-2022-23666, CVE-2022-23672, CVE-2022-23673)

    - A command injection vulnerability exists in Aruba ClearPass Policy Manager. An authenticated, remote attacker can
    exploit this to execute arbitrary commands. (CVE-2022-23665)

    - A command injection vulnerability exists in the ClearPass Policy Manager command line interface. An authenticated,
    remote attacker can exploit this to execute arbitrary commands. (CVE-2022-23667)

    - A Server Side Request Forgery (SSRF) vulnerability exists in the web-based management interface of ClearPass Policy
    Manager due to improper validation of session & user-accessible input data. The insecure processing of the input by
    the vulnerable application server allows an unauthenticated, remote attacker the ability to exploit this by sending a
    specially crafted message to the server to create a trusted remote session with a malicious external target.
    (CVE-2022-23668)

    - An authentication bypass vulnerability exists in ClearPass Policy Manager due to the handling of SAML token expiration.
    An authenticated, remote attacker can exploit this, via possession of a valid token to reuse the token after session
    expiration, to bypass authentication and execute arbitrary actions with user privileges. (CVE-2022-23669)

    - An information disclosure vulnerability exists in ClearPass Policy Manager cluster network position. An authenticated,
    remote attacker can exploit this to disclose potentially sensitive information. (CVE-2022-23671)

    - A authenticated stored cross-site scripting (XSS) vulnerability exists in the web-based management interface of ClearPass
    Policy Manager due to improper validation of user-supplied input before returning it to users. An authenticated,
    remote attacker can exploit this, by convincing a user to click a specially crafted URL, to execute arbitrary script code
    in a user's browser session. (CVE-2022-23674, CVE-2022-23675)


Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2022-007.txt");
  script_set_attribute(attribute:"solution", value:
"Please see vendor advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23660");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:arubanetworks:clearpass");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("aruba_clearpass_polman_detect.nbin");
  script_require_keys("Host/Aruba_Clearpass_Policy_Manager/version");

  exit(0);
}

include('vcf.inc');

var app = 'Aruba ClearPass Policy Manager';
var app_info = vcf::get_app_info(app:app, kb_ver:'Host/Aruba_Clearpass_Policy_Manager/version');

constraints = [
  { 'min_version' : '6.10', 'max_version' : '6.10.4', 'fixed_display': 'Please see vendor advisory'},
  { 'min_version' : '6.9', 'max_version' : '6.9.9', 'fixed_display': 'Please see vendor advisory'},
  { 'min_version' : '6.0', 'max_version' : '6.8.9-HF2', 'fixed_display': 'Please see vendor advisory'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
