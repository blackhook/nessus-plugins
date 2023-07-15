#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2021/06/01. Deprecated due to FN issues with jscript & cumulative updates.
include("compat.inc");

if (description)
{
  script_id(129167);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/30");

  script_cve_id("CVE-2019-1367");
  script_xref(name:"MSKB", value:"4522009");
  script_xref(name:"MSKB", value:"4522010");
  script_xref(name:"MSKB", value:"4522011");
  script_xref(name:"MSKB", value:"4522012");
  script_xref(name:"MSKB", value:"4522014");
  script_xref(name:"MSKB", value:"4522015");
  script_xref(name:"MSKB", value:"4522016");
  script_xref(name:"MSFT", value:"MS19-4522009");
  script_xref(name:"MSFT", value:"MS19-4522010");
  script_xref(name:"MSFT", value:"MS19-4522011");
  script_xref(name:"MSFT", value:"MS19-4522012");
  script_xref(name:"MSFT", value:"MS19-4522014");
  script_xref(name:"MSFT", value:"MS19-4522015");
  script_xref(name:"MSFT", value:"MS19-4522016");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Windows 10, Server 2016 and Server 2019 September 2019 Security Update (CVE-2019-1367) (deprecated)");
  script_summary(english:"Checks for rollup.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The plugin has been deprecated because it is preventing the reporting of valid vulnerabilities due to the way 
Microsoft handles the jscript file");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4522009");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4522010");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4522011");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4522012");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4522014");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4522015");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4522016");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1367
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6fcaf7ca");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1367");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}
exit(0, "This plugin has been deprecated to properly flag the detection of missing Microsoft Security updates between Feb & Oct 2019.");