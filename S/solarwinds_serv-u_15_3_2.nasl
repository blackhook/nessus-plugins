#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2022/12/14. Deprecated because the advisory was removed.
#
##

include('compat.inc');

if (description)
{
  script_id(168137);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id("CVE-2022-38106");
  script_xref(name:"IAVA", value:"2023-A-0010");

  script_name(english:"SolarWinds Serv-U 15.3.0 < 15.3.2 (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The version of SolarWinds Serv-U installed on the remote host is prior to 15.3.2. It is, therefore, affected by a
vulnerability as referenced in the serv-u_15_3_2 advisory.

  - This vulnerability happens in the web client of Serv-U 15.3.1 and earlier release version. When the
    payload is entered in the directory creation option, it will throw an error and then the payload executes.
    (CVE-2022-38106)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.

This plugin has been deprecated because the vendor's advisory has been removed.");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2022-38106
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a103b9da");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38106");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:serv-u");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:serv-u_file_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:serv-u:serv-u");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("servu_version.nasl");
  script_require_keys("installed_sw/Serv-U");

  exit(0);
}

exit(0, 'This plugin has been deprecated.');
