#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2021/04/15. Deprecated due to non-security patch check

include('compat.inc');

if (description)
{
  script_id(148463);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/27");
  script_xref(name:"MSKB", value:"5001638");
  script_xref(name:"MSFT", value:"MS21-5001638");

  script_name(english:"KB5001638: Windows 10 version 1809 OOB Update (Mar 2021) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing an out-of-band security update. Note that
Nessus has not tested for this issue but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5001638");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB5001638 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21199");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}
exit(0, "This plugin has been deprecated because it is a non-security patch check.");
