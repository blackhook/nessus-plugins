#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110290);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_xref(name:"IAVB", value:"2018-B-0068-S");

  script_name(english:"Bitvise SSH Server < 7.41 Multiple Vulnerabilities");
  script_summary(english:"Checks the Bitvise SSH Server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Bitvise SSH Server installed on the remote Windows
host is prior to 7.41. It is, therefore, affected by multiple
vulnerabilities.");
  # https://www.bitvise.com/flowssh-version-history#security-notification-741
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6bf2994b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Bitvise SSH Server 7.41 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bitvise:ssh_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bitvise_ssh_server_installed.nbin");
  script_require_keys("installed_sw/Bitvise SSH Server", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
app_info = vcf::get_app_info(app:"Bitvise SSH Server", win_local:TRUE);

constraints = [{ "fixed_version" : "7.41" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
