#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122858);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/30 13:24:47");

  script_cve_id("CVE-2018-9190");

  script_name(english:"Fortinet FortiClient NDIS Miniport Driver Null Pointer Dereference");
  script_summary(english:"Checks the version of FortiClient.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Fortinet FortiClient running on the remote host is
prior to 6.0.3. It is, therefore, affected by a NULL pointer dereference
flaw due to a failure to utilize necessary NULL checks before doing
indirect function calls. An unauthenticated, local attacker can exploit
this, via the NDIS Miniport drivers, to cause a denial of service
condition when the application attempts to read or write memory with
a NULL pointer.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-18-092");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiClient 6.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-9190");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:forticlient");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("forticlient_detect.nbin");
  script_require_keys("installed_sw/FortiClient", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("installed_sw/FortiClient");
app_info = vcf::get_app_info(app:"FortiClient");

constraints = [
  {"fixed_version" : "6.0.3"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
