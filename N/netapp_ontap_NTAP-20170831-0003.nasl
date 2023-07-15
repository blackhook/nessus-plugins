#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103970);
  script_version("1.4");
  script_cvs_date("Date: 2018/07/17 12:00:07");

  script_cve_id("CVE-2016-1895");

  script_name(english:"NetApp Clustered Data ONTAP < 8.2.5 / 8.3.x < 8.3.2P12 (NTAP-20170831-0003)");
  script_summary(english:"Checks the version of ONTAP.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of NetApp Clustered Data ONTAP running on the remote
host is prior to 8.2.5 or 8.3.x prior to 8.3.2P12. It is, therefore,
affected by an unspecified flaw in the handling of certain user input
strings which allow an authenticated user to cause a Denial of Service
(DoS) condition.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://kb.netapp.com/support/s/article/NTAP-20170831-0003?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1aabfc5d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NetApp Clustered Data ONTAP version 8.2.5 / 8.3.2P12 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:netapp:data_ontap");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("netapp_ontap_detect.nbin");
  script_require_keys(
    "Host/NetApp/ONTAP/display_version",
    "Host/NetApp/ONTAP/version",
    "Host/NetApp/ONTAP/mode",
    "Host/NetApp/ONTAP/cluster"
  );

  exit(0);
}

include("vcf.inc");

app_name = "NetApp ONTAP";

mode = get_kb_item_or_exit("Host/NetApp/ONTAP/mode");
cluster = get_kb_item_or_exit("Host/NetApp/ONTAP/cluster");

# detection should find 7-mode or Clustered mode
if (!mode && !cluster)
  audit(AUDIT_OS_CONF_NOT_VULN, app_name);

app_info = vcf::get_app_info(app:app_name, kb_ver:"Host/NetApp/ONTAP/display_version");

vcf::check_granularity(app_info:app_info, sig_segments:2);

# There is some mode overlap for 8.1.x and 8.2.x:
#   Clustered mode is available in 8.1 and later
#   7-mode is only available through 8.2.x

# Splitting logic so clustered mode < 8.3.2P12 and 7-mode < 8.2.5
if (cluster)
{
  # Clustered Data ONTAP 8.1 < 8.3.2P12
  constraints = [
    { "min_version" : "8.1",  "fixed_version" : "8.3.2P12" }
  ];
}
else
{
  # Data ONTAP operating in 7-Mode < 8.2.5
  constraints = [
    { "min_version" : "0",  "fixed_version" : "8.2.5" }
  ];
}

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
