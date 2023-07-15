#TRUSTED 9cbc815dcea1d488273527fd74573a91e388fe7ea74c1c769a4b43be8f7d9d7be8a46daa6db39f1cbb5f14e0006e21154ba6da9bd51337fe5afd4d76e6eee7d2cfa2e8998b00e913bd56d61c476ed482a6b54a04b078fea8b3fe341f5cbf55a50819861db2ee38f2b4eed9ec5e7f5d2076bb8521908c5870561ce95ee376fa0d2d33bf60e92d0280ab5d6cbeb04cfb545fc4bc5f035006ead3bd7fb98c3c222841a92886317c92f2b85a1572a0d3a7c4c3f7c3fcc01e34191f46695a3d090b3de1ef57505d00216de93e33413629c89f506b8d167088838f66bf7382b8762c537b08d1d71aa31f60bbc5210759e3657cd7b8d8d949027ed671c2c37747fd27cf8c9b32627e42bf7adb72513db52489c6204b79d6f509729325a2bc7a7de2afcae04729041582a71d30399ab49caba58b9dfec2af80d902b93d26b55b3a079aaef2522afe4422a42723ac9dc4cacb2404957bc7606540c7339f4d3909abc2a5f4aee9805c533401e1a45986737e4f7c138787ba5f1f3b49fd333129ed4c04cf6c646c1fbdb7ae23bbf7fbdf2e74721c4ca792d8b1c6b6a886812bce6db969b4a0efcb62e29925ff3f7db03a100a7eb3ac72e6bcdfce270f759e935397d4f231ad2828799b2d600de4d6b6898d22cb573f50f3aa95c4078018167dc67601a1ab6863590fc10e366ff7902821ae96e1354b2257dd9ccac8740910866d115c630eff
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148677);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/02");

  script_cve_id("CVE-2021-0246");
  script_xref(name:"JSA", value:"JSA11139");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11139)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11139
advisory. Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11139");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11139");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0246");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(SRX15[0-9]{2}|SRX41[0-9]{2}|SRX42[0-9]{2}|SRX46[0-9]{2}|SRX5[0-9]{3})([^0-9]|$)|SRX5K")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'18.3R1', 'fixed_ver':'18.3R3'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R2'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R2'}
];

# Version Check
var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var affected_spc = FALSE;

# SPC check
var buf = junos_command_kb_item(cmd:'show chassis hardware models');
if (junos_check_result(buf))
{
  override = FALSE;

  # SPC2
  if (buf =~ "SPC-?2")
    affected_spc = TRUE;

  # SPC3
  if (buf =~ "SPC-?3" && ver !~ "^18.3")
    affected_spc = TRUE;
}

if (!affected_spc)
  audit(AUDIT_HOST_NOT, 'using an affected SPC');

# Tenant config check
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (junos_check_result(buf))
{
  override = FALSE;
  # Checking for a tenant login class and some other tenant configuration should be good enough
  if (
    !(junos_check_config(buf:buf, pattern:"^set system login class.*tenant")
        && junos_check_config(buf:buf, pattern:"^set tenants.*(interfaces|routing-instances)")
      )
    )
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
