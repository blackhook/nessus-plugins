#%NASL_MIN_LEVEL 80900
##
#
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2022/09/22. Deprecated by securitycenter_5_22_0_tns_2022_07.nasl.
##

include('compat.inc');

if (description)
{
  script_id(164841);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/04");

  script_cve_id("CVE-2022-31129");
  script_xref(name:"IAVA", value:"2023-A-0059");

  script_name(english:"Tenable SecurityCenter 5.19.x / 5.20.x / 5.21.0 Moment.js Denial of Service (TNS-2022-18) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated and replaced with plugin ID 163634.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2022-18");
  # https://docs.tenable.com/releasenotes/Content/tenablesc/tenablesc2022091.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7cba126f");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31129");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_ports("installed_sw/Tenable SecurityCenter");

  exit(0);
}

exit(0, 'This plugin has been deprecated and replaced with plugin ID 163634.');