#TRUSTED 8cef261bd973130abd326a2778a949b0ff61bc383e17bd31599b8c432629a5d8642d19a5186456d934a3d39079a7182e81c405cdafed8a2a40cfa87716bbc68955cfcd9c516ee1433a4a07ef8829d8a340c8472046e5aaed31effe8a9cfbf07ba6c92315cad9a1b18c1c5cbb881a7990bb054eec9548f74310e1d83d9aaa95bb97aeb18035bfd8413d6d10f63a46a36ba0aec626c852508a2922d8c2e1c4a4bedfe3c10a5cf68ca28fd6914f38596b943cf9e8d6d1ac7487369319e3272ee54794f7d738043beb38ebf81b425c93bdb7f45f12a68e46ca812f2b5975f4461774fae2d0f9180434ff8818fb094756c6644e689dd57fbbf77df616df32c71807b645ae048bcce9aa00ee7587241af41aa0c641f07cff877fc11b3f75bb012ae7433ee5370a8da99d5b60e15622488db07ede5dc1fb3a404c25de6ea912d328fecef7547c58d4c2266000ca4a5242a4bc14582aece6845cefec5119927c3f5317276a409304596895618b3fa8766fc7dae440edd2b1f3d3047856f15962ef62c2de174d27f4dad4e1abafc4b33660c513db4fab6e5c01286e3137c55c9ed086ab3aa6fcb3febf830c72a334278fae140bbbcfed0f8a19578ef0774c2100253ee32a6159cfe445358cb1b4386c4a70c3de538b291d25a004a1ca088d9cf4cd0343d689c09691cc989a9557ffebdaeb0c361866e59cf10b41eb01217d8e7a6ee90e5e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102704);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2017-2343");
  script_xref(name:"JSA", value:"JSA10791");

  script_name(english:"Juniper Junos SRX Integrated User Firewall Hardcoded Credentials (JSA10791)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the remote
Juniper Junos device has hardcoded credentials for the Integrated User
Firewall (UserFW) services authentication API. An unauthenticated,
remote attacker can exploit this to gain administrative access to the
device.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10791");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
security advisory JSA10791.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

check_model(
  model:model,
  flags:SRX_SERIES,
  exit_on_fail:TRUE
);

fixes = make_array();

if(ver =~ "12\.3X48-D3\d([^0-9]|$)")
  fixes['12.3X48'] = '12.3X48-D35';
if(ver =~ "15\.1X49-D4\d([^0-9]|$)")
  fixes['15.1X49'] = '15.1X49-D50';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show services user-identification active-directory-access domain-controller status extensive");
if (buf)
{
  override = FALSE;
  pattern = "^Status: Connected";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as it does not appear to have User Integrated Firewall enabled.');
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
