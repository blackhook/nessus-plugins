#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104175);
  script_version("1.4");
  script_cvs_date("Date: 2018/07/13 15:08:46");

  script_cve_id(
    "CVE-2017-10622"
  );
  script_bugtraq_id(
    101258
);
  script_xref(name:"JSA", value:"JSA10824");

  script_name(english:"Juniper Junos Space 17.1 < 17.1R1 Patch v1 / 16.1 < 16.1R3 Authentication Bypass (JSA10824)");
  script_summary(english:"Checks the version of Junos Space.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Junos
Space running on the remote device is 17.1 < 17.1R1.1 or 
16.1 < 16.1R3, and is therefore affected by an authentication
bypass vulnerability.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10824&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c373879e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Junos Space version 17.1R1 with Patch v1 / 16.1R3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_space");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Junos_Space/version");

  exit(0);
}

include("audit.inc");
include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Junos_Space/version');

if ( ver =~ '^17\\.[01]' )
  check_junos_space(ver:ver, fix:'17.1R1.1', severity:SECURITY_HOLE);
else if (ver =~ '^16\\.[01]')
  check_junos_space(ver:ver, fix:'16.1R3', severity:SECURITY_HOLE);
else audit(AUDIT_INST_VER_NOT_VULN, "Junos Space", ver);
