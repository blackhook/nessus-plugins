#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135973);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-7080",
    "CVE-2020-7081",
    "CVE-2020-7082",
    "CVE-2020-7083",
    "CVE-2020-7084",
    "CVE-2020-7085"
  );
  script_xref(name:"IAVA", value:"2020-A-0170");
  script_xref(name:"CEA-ID", value:"CEA-2020-0036");

  script_name(english:"Autodesk FBX-SDK library <= 2019.5 Multiple Vulnerabilities (ADSK-SA-2020-0002)");

  script_set_attribute(attribute:"synopsis", value:
"The Autodesk FBX-SDK library installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Autodesk FBX-SDK library installed on the remote host is prior to 2019.5. It is, therefore, affected by
the following vulnerabilities :

  - A buffer overflow vulnerability in the Autodesk FBX-SDK may lead to arbitrary code execution on a system
    running it. (CVE-2020-7080)

  - A type confusion vulnerability in the Autodesk FBX-SDK may lead to arbitary code read/write on the system
    running it. (CVE-2020-7081)

  - A use-after-free vulnerability in the Autodesk FBX-SDK may lead to code execution on a system running it.
    (CVE-2020-7082)

  - An intager overflow vulnerability in the Autodesk FBX-SDK may lead to denial of service of the
    application. (CVE-2020-7083)

  - A NULL pointer dereference vulnerability in the Autodesk FBX-SDK may lead to denial of service of the
    application. (CVE-2020-7084)

  - A heap overflow vulnerability in the Autodesk FBX-SDK may lead to arbitrary code execution on a system
    running it. (CVE-2020-7085)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.autodesk.com/trust/security-advisories/adsk-sa-2020-0002");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Autodesk FBX-SDK library version 2020 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7085");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-7082");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:fbx_software_development_kit");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("autodesk_fbx-sdk_detect_win.nbin");
  script_require_keys("installed_sw/FBX SDK");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'FBX SDK');

constraints = [
  { 'max_version' : '2019.5', 'fixed_version' : '2020' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
