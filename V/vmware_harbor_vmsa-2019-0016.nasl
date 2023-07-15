#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130153);
  script_version("1.3");
  script_cvs_date("Date: 2020/01/14");

  script_cve_id("CVE-2019-16919");
  script_xref(name:"VMSA", value:"2019-0016");

  script_name(english:"VMware Harbor 1.8.x < 1.8.4 (VMSA-2019-0016)");

  script_set_attribute(attribute:"synopsis", value:
"A cloud native registry installed on the remote host is affected by a broken access control vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Harbor installed on the remote host is 1.8.x prior to 1.8.4. It is, therefore, affected by a
broken access control vulnerability due to a failure to enforce proper project permissions and project scope on the API
request to create a new robot account. This vulnerability allows project administrators to use the Harbor API to create
a robot account with unauthorized push and/or pull access permissions to a project they don't have access to or control
over.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2019-0016.html");
  script_set_attribute(attribute:"solution", value:
"Update to VMware Harbor version 1.8.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16919");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:goharbor:harbor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cncf_harbor_web_detect.nbin", "cncf_harbor_local_detect.nbin");
  script_require_keys("installed_sw/Harbor");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('installed_sw/Harbor');

app_info = vcf::combined_get_app_info(app:'Harbor');

constraints = [
  { 'min_version' : '1.8', 'fixed_version' : '1.8.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
