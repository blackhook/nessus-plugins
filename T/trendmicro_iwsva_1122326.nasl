#
# (C) Tenable Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(133361);
  script_version("1.2");
  script_cvs_date("Date: 2020/01/31");

  script_cve_id("CVE-2019-9490");
  script_bugtraq_id(107848);

  script_name(english:"Trend Micro InterScan Web Security Virtual Appliance (IWSVA) Information Disclosure Vulnerability (1122250)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an application that is affected by an information disclosure vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Trend 
  Micro InterScan Web Security Virtual Appliance is affected by an information disclosure vulnerability in its web 
  console component. An authenticated, remote attacker can exploit this, to disclose credentials of the web console
  administrator.

  Note that Nessus has not tested for this issue but has instead relied solely on the application's self-reported 
  version number.");
  # https://success.trendmicro.com/solution/1122326
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7aad0444");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the IWSVA version 6.5 build 1852 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9490");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("trendmicro_iwsva_version.nbin");
  script_require_keys("Host/TrendMicro/IWSVA/version", "Host/TrendMicro/IWSVA/build", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');

version = get_kb_item_or_exit('Host/TrendMicro/IWSVA/version');
build = get_kb_item_or_exit('Host/TrendMicro/IWSVA/build');

# Detection doesn't guarantee SP version - Vuln only affects SP2 so making paranoid 
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

# Detection may report the build as 'Unknown'
if (build == 'Unknown')
  exit(1, 'Unable to accurately determine the build number of the InterScan Web Security Virtual Appliance install');

fixed_build = '1852';
if (!(version =~ '^6\\.5') || ver_compare(ver:build, fix:fixed_build, strict:FALSE) >= 0)
  audit(AUDIT_HOST_NOT, 'affected');

report =
  '\n  Installed version : 6.5 Build ' + build +
  '\n  Fixed version     : 6.5 Build ' + fixed_build +
  '\n';

security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
