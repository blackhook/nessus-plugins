#TRUSTED 92dbabbb9aa86b98732e679cbabd71bd8eb6808ba5952c36160d07ad7f96636d80e8c13514a858b17b4361ea616387c5792a6a63e15f31bfac5564cc45d1bd3c6d73ab65674dcbe5984af69ac6fe009ca7b02d5ed3205a32bdd92d1761789dc56d1c7ac855dea7533314f7fb5b95ebf45c4cfd912af7f2133d852561981d697668152ad26fa819e35737a1296fb2ad939084e92812fa3d09e4cef4b8882a29829548cdef289bcc5e6a6b76bfcd42c4297a53a1bd151db465809da5b8e23e9aa2b5d5210a15156a2ebdaedd448f336dea328adb5b6766ba9d82d429495c173441586b139a73d57b1403b729f5cb9ca46ed232e8a2db4d2764357294c8eb99ab898f0bed868a94a5abc799fdb79a89729345fa03dd67a6fb4b1965dd25ef209de851ba4a298d07d52b83f1d26ed20070153887531697f66a40f834c7c1af93230bb781b65cbe225d4cda35f1764369c9a05297df5637ed79a2f1be76540edfce30c93c8a0b1fabdce3a8862935bc0d06b208d5400d3e787f30a6f683c6b3c52228a89734fd933cdedb0a5cd71260aae02d28a6f5885f01cb16f6537888ed256cd1599c0937cf16075bee4f005b517da69e03ddeb895ca234a0674ddb0d17e511f9de734657f4ea9f3e55f747a5aec31d275bf6e6b1e2ecb967baa3bc2d8b0eace7e20cb54909a64016cfcf9fde2e5636d04768b45a981afe175bfbc2fc7765cb71
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80954);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2014-6383");
  script_bugtraq_id(72071);
  script_xref(name:"JSA", value:"JSA10666");

  script_name(english:"Juniper Junos MX Series Trio-based PFE Modules Security Bypass (JSA10666)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos MX series device is affected by a security bypass vulnerability
when processing stateless firewall filters on a device with Trio-based
PFE modules with IPv4 filters. A remote attacker can exploit this
issue to bypass stateless firewall filters.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10666");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10666.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

check_model(model:model, flags:MX_SERIES, exit_on_fail:TRUE);

fix = NULL;

# Only versions 13.3R3, 14.1R1, and 14.1R2 are affected
if (ver =~ "^13\.3R3$")
  fix = "13.3R3-S3 / 13.3R4";
else if (ver =~ "^14\.1R[12]$")
  fix = "14.1R3 / 14.2R1";
else
  audit(AUDIT_INST_VER_NOT_VULN, "Junos", ver);

override = TRUE;
buf = junos_command_kb_item(cmd:"show chassis hardware");
if (buf)
{
  # Trio-based PFE modules part numbers
  #  https://kb.juniper.net/InfoCenter/index?page=content&id=KB25385
  part_numbers = make_list(
    "750-028381",
    "750-031087",
    "750-028395",
    "750-031092",
    "750-038489",
    "750-038490",
    "750-031089",
    "750-028393",
    "750-028391",
    "750-031088",
    "750-028394",
    "750-031090",
    "750-024884",
    "750-038491",
    "750-038493",
    "750-038492",
    "750-028467",
    "711-031594",
    "711-031603",
    "711-038215",
    "711-038213",
    "711-038211",
    "711-038634"
  );

  foreach part_number (part_numbers)
  {
    if (part_number >< buf)
    {
      override = FALSE;
      break;
    }
  }
  if (override) audit(AUDIT_HOST_NOT,
    'affected because no Trio-based PFE modules were found');
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
