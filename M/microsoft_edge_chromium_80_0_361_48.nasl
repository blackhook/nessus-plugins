#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138174);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id(
    "CVE-2019-18197",
    "CVE-2019-19880",
    "CVE-2019-19923",
    "CVE-2019-19925",
    "CVE-2019-19926",
    "CVE-2020-6381",
    "CVE-2020-6382",
    "CVE-2020-6385",
    "CVE-2020-6387",
    "CVE-2020-6388",
    "CVE-2020-6389",
    "CVE-2020-6390",
    "CVE-2020-6391",
    "CVE-2020-6392",
    "CVE-2020-6393",
    "CVE-2020-6394",
    "CVE-2020-6395",
    "CVE-2020-6396",
    "CVE-2020-6397",
    "CVE-2020-6398",
    "CVE-2020-6399",
    "CVE-2020-6400",
    "CVE-2020-6401",
    "CVE-2020-6402",
    "CVE-2020-6404",
    "CVE-2020-6405",
    "CVE-2020-6406",
    "CVE-2020-6408",
    "CVE-2020-6409",
    "CVE-2020-6410",
    "CVE-2020-6411",
    "CVE-2020-6412",
    "CVE-2020-6413",
    "CVE-2020-6414",
    "CVE-2020-6415",
    "CVE-2020-6416",
    "CVE-2020-6417"
  );

  script_name(english:"Microsoft Edge (Chromium) < 80.0.361.48 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge (Chromium) installed on the remote Windows host is prior to 80.0.361.48. It is, therefore,
affected by multiple vulnerabilities:

  - An integer overflow condition exists in the JavaScript component of Google Chrome. An unauthenticated,
    remote attacker can exploit this, via a crafted HTML page, to potentially exploit heap corruption.
    (CVE-2020-6381)

  - A type confusion error exists in the JavaScript component of Google Chrome. An unauthenticated, remote
    attacker can exploit this, via a crafted HTML page, to potentially exploit heap corruption.
    (CVE-2020-6382)

  - A use-after-free vulnerability exists in the speech component of Google Chrome. An unauthenticated, remote
    attacker can exploit this, via a crafted HTML page, to potentially exploit heap corruption.
    (CVE-2020-6406)

In addition, Microsoft Edge (Chromium) is also affected by several additional vulnerabilities including additional
use-after-free vulnerabilities, out-of-bounds read/write, insufficient input validation, and insufficient policy
enforcements.");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV200002
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b4f0f972");
  # https://docs.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ec7f076");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge (Chromium) 80.0.361.48 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6416");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_chromium_installed.nbin");
  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);

constraints = [{ 'fixed_version' : '80.0.361.48' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

