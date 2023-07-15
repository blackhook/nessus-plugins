#%NASL_MIN_LEVEL 80900
##
#
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2022/05/12. Deprecated by veritas_netbackup_VTS23-006.nasl.
##

include('compat.inc');

if (description)
{
  script_id(174480);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/12");

  script_cve_id("CVE-2023-28759");
  script_xref(name:"IAVA", value:"2023-A-0181");

  script_name(english:"Veritas NetBackup prior to 10.0 Privilege Escalation (VTS22-010#M2) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"CVE-2023-28759 was part of VTS22-010#M2 but is not any longer. It now appears on its own separate advisory, VTS23-006.
A plugin for that advisory has replaced this one.");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/content/support/en_US/security/VTS22-010#M2");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28759");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:veritas:netbackup");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("installed_sw/NetBackup");

  exit(0);
}
exit(0, 'This plugin has been deprecated. Use veritas_netbackup_VTS23-006.nasl instead.');
