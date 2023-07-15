#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(126917);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/29");

  script_cve_id("CVE-2018-0047");
  script_bugtraq_id(108494);
  script_xref(name:"JSA", value:"JSA10881");

  script_name(english:"Juniper Junos Space < 17.2R2 Persistent XSS Vulnerability (JSA10881)");
  script_summary(english:"Checks the version of Junos Space.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a persistent cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Junos
Space running on the remote device is < 17.2R2, and is therefore
affected by a persistent cross-site scripting vulnerability in the UI
framework used by Junos Space Security Director. A remote authenticated
attacker can exploit that to inject persistent and malicious scripts,
steal information or perform actions.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10881");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Junos Space version 17.2R2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0047");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_space");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Junos_Space/version");

  exit(0);
}

include('junos.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Junos_Space/version');

check_junos_space(ver:ver, fix:'17.2R2', severity:SECURITY_NOTE,  xss:TRUE);
