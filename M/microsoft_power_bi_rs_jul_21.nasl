#%NASL_MIN_LEVEL 70300
##
#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2021/10/14. Deprecated because this impacts Power BI Desktop, not the server
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(151623);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/25");

  script_cve_id("CVE-2021-31984");

  script_name(english:"Security Update for Microsoft Power BI Report Server (July 2021) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"Deprecated because the exposure impacts Power BI Desktop");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31984
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c636e459");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31984");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:power_bi_report_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_power_bi_rs_win_installed.nbin");
  script_require_keys("installed_sw/Microsoft Power BI Report Server");

  exit(0);
}

exit(0, 'This plugin has been deprecated because the exposure does not impact Microsoft Power BI Server');
