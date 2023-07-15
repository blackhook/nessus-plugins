#TRUSTED 74de6d09bfd72d99ce87fa25ed5e6197d12a8adf26bf45cd96c58662da28a39c54602d213cb724355abe67e6e90b840bf4bda8a67f40bac4d4c10be84e22ff4b9af9cc06ceb8ad5ebecd102d8db1b2f7f98d1d8700ae4a1eeeccb1572923cdbbc6b4acac75f7ae97e4afd5ea3c636dd691abf3be8faf0db88fdea44dd69028c7f38ce5202f3c5406419c31c4435d2c4563e5bb7cde97e761e09e7f529bbe4222a08952ff5d7c75e7c12b7a7499414d2e544176f8c175e00948d062106a74563d17d6b8926ae90e00fc63804f8e2482d37815760b1d3914c0e8776ca4fa5b974f42207b2a45f57df603114f2fb4fcb15d05d2c7386aa69c8bf73bad7936c021eebdd8cd4a73218487493aa04f568f2aea1dc5a830c458e4b8153e62363faf4ccf43ae0ec517b17fa2a42e15e3ee0b74f5f7afea14ee601548bd24eafc873fd7bf7039c79357ca36a2e55fbe52e9d5fa576189e0a79212260122fba5791d9fe1521b16a7fd0cd5f5b3bfe47a79637a97efa23a3374bd7c551c047a0078966a5c62111adb3b311c527c242eb2463336592a6fd5f6859cb89a4aab1dd24148d6e6113a57b84964e664252a7e7ecfcb23eb18d80f4f56ec17df30c53c937c5ccd8c861543eff6d9b77611cbce225c14cf3ac7e5d30a48a416dd5fad303244ce74abceab41ed182508dcd888c0a80d0bb8708b22d9b5faaa74ac8b3b2cc40d2737d3b6
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(60024);
  script_version ("1.4");

  script_name(english:"ADSI Settings");
  script_summary(english:"ADSI settings parameters.");

  script_set_attribute(attribute:"synopsis", value:"Set the ADSI query parameters for plugins using ADSI.");
  script_set_attribute(attribute:"description", value:"Gather and store the ADSI parameters
to be used in other plugins.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/06");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/06/22");
  script_set_attribute(attribute: "plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Settings");

  script_add_preference(name:"Domain Controller : ", type:"entry", value:"");
  script_add_preference(name:"Domain : ", type:"entry", value:"");
  script_add_preference(name:"Domain Username : ", type:"entry",    value:"");
  script_add_preference(name:"Domain Password : ", type:"password", value:"");

  for (i=2; i<=5; i++)
  {
    script_add_preference(name:"Domain Controller "+i+": ", type:"entry", value:"");
    script_add_preference(name:"Domain "+i+": ", type:"entry", value:"");
    script_add_preference(name:"Domain Username "+i+": ", type:"entry",    value:"");
    script_add_preference(name:"Domain Password "+i+": ", type:"password", value:"");
  }

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

host      = script_get_preference("Domain Controller : ");
domain    = script_get_preference("Domain : ");
username  = script_get_preference("Domain Username : ");
password  = script_get_preference("Domain Password : ");

if (!username && !password && !host && !domain)
{
  exit(0, "ADSI settings are not set.");
}
else if (!username || !password || !host || !domain)
{
  exit(1, "One or more settings are set but not all settings are set.");
}

set_kb_item(name:"adsi/host/0" , value:host );
set_kb_item(name:"adsi/domain/0" , value:domain );
set_kb_item(name:"Secret/adsi/username/0" , value:username );
set_kb_item(name:"Secret/adsi/password/0" , value:password );

n = 1;

for (i=2; i<=5; i++)
{
  # Get the preference values
  host      = script_get_preference("Domain Controller "+i+": ");
  domain    = script_get_preference("Domain "+i+": ");
  username  = script_get_preference("Domain Username "+i+": ");
  password  = script_get_preference("Domain Password "+i+": ");
  if (!username || !password || !host || !domain) continue;

  set_kb_item(name:"adsi/host/"+n+"" , value:host );
  set_kb_item(name:"adsi/domain/"+n+"" , value:domain );
  set_kb_item(name:"Secret/adsi/username/"+n+"" , value:username );
  set_kb_item(name:"Secret/adsi/password/"+n+"" , value:password );
  n++;
}
