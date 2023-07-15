#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(126508);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/05");

  script_cve_id("CVE-2018-0044");
  script_bugtraq_id(105565);
  script_xref(name:"JSA", value:"JSA10878");

  script_name(english:"NFX Series: Insecure sshd configuration in Juniper Device Manager (JDM) and host OS (JSA10878)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a vulnerability. With an insecure SSHD 
configuration in Juniper Device Manager, a remote, unauthenticated 
attacker can gain access if any of the passwords on the system are
empty. The affected SSHD configuration has the PermitEmptyPasswords
option set to 'yes'.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10878");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10878.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0044");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('audit.inc');
include('junos.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if ( 'NFX' >!< model)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes['18.1'] = '18.1R4';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
