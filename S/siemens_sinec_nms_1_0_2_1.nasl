##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162727);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2021-33722",
    "CVE-2021-33723",
    "CVE-2021-33724",
    "CVE-2021-33725",
    "CVE-2021-33726",
    "CVE-2021-33727",
    "CVE-2021-33728",
    "CVE-2021-33729",
    "CVE-2021-33730",
    "CVE-2021-33731",
    "CVE-2021-33732",
    "CVE-2021-33733",
    "CVE-2021-33734",
    "CVE-2021-33735",
    "CVE-2021-33736"
  );

  script_name(english:"Siemens SINEC NMS < V1.0 SP2 Update 1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"Siemens SINEC NMS Server installed on the remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Siemens SINEC NMS Server installed on the remote host is affected by multiple vulnerabilities,
including the following:

  - A vulnerability has been identified in SINEC NMS (All versions < V1.0 SP2 Update 1). The affected system allows to upload JSON objects that are deserialized to JAVA objects. Due to insecure deserialization of user-supplied content by the affected software, a privileged attacker could exploit this vulnerability by sending a crafted serialized Java object. An exploit could allow the attacker to execute arbitrary code on the device with root privileges. (CVE-2021-33728)

  - A vulnerability has been identified in SINEC NMS (All versions < V1.0 SP2 Update 1). An authenticated attacker that is able to import firmware containers to an affected system could execute arbitrary commands in the local database. (CVE-2021-33729)

  - A vulnerability has been identified in SINEC NMS (All versions < V1.0 SP2 Update 1). The affected system contains an Arbitrary File Deletion vulnerability that possibly allows to delete an arbitrary file or directory under a user controlled path. (CVE-2021-33724)

  - A vulnerability has been identified in SINEC NMS (All versions < V1.0 SP2 Update 1). A privileged authenticated attacker could execute arbitrary commands in the local database by sending crafted requests to the webserver of the affected application. (CVE-2021-33736)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cert-portal.siemens.com/productcert/pdf/ssa-163251.pdf");
  # https://claroty.com/2022/06/16/blog-research-securing-network-management-systems-part-3-siemens-sinec-nms/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e898f4ea");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Siemens SINEC NMS Server version 11 Update 3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33728");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-33725");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:siemens:sinec_nms");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("siemens_sinec_nms_win_installed.nbin");
  script_require_keys("installed_sw/SINEC NMS");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'SINEC NMS');
var constraints = [{'fixed_version': '1.0.2.1', 'fixed_display': 'V1.0 SP2 Update 1'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
