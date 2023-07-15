#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103875);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-13078",
    "CVE-2017-13079",
    "CVE-2017-13080",
    "CVE-2017-13081",
    "CVE-2017-13082",
    "CVE-2017-13084",
    "CVE-2017-13086",
    "CVE-2017-13087",
    "CVE-2017-13088"
  );
  script_bugtraq_id(101274);
  script_xref(name:"IAVA", value:"2017-A-0310");

  script_name(english:"Ubiquiti Networks UniFi < 3.9.3.7537 (KRACK)");
  script_summary(english:"Checks UniFi version");

  script_set_attribute(attribute:"synopsis", value:
"The remote networking device is affected by KRACK.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote networking device is running
a version of UniFi OS prior to 3.9.3.7537. It, therefore, vulnerable to multiple
vulnerabilities discovered in the WPA2 handshake protocol.");
  # https://community.ubnt.com/t5/UniFi-Updates-Blog/FIRMWARE-3-9-3-7537-for-UAP-USW-has-been-released/ba-p/2099365
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca6adaa9");
  script_set_attribute(attribute:"see_also", value:"https://www.krackattacks.com/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to UniFi OS 3.9.3.7537 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-13082");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:ubnt:unifi");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/UBNT_UniFi/Version");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("Host/UBNT_UniFi/Version");

app_info = vcf::get_app_info(app:"UBNT UniFi", kb_ver:"Host/UBNT_UniFi/Version", port:22);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
    { "fixed_version" : "3.9.3.7537" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
