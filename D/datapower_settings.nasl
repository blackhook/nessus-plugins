#TRUSTED 32a2e8bb4afe33d58066ed961085c1c6b4ba3c2af6f357f92ed29c6a8f33fee684426e76d50b92e99d77fabd93b9b10b76da32b3d8152c53bbb4ffe02380dee45aa7eab23e831cb24ea35bee1c963542e123b92bcd53985a3f474c7b13a1f2f4365d35f961ecc2aa8612b5e5e83493c7a06000a096e0a49c73a4f8b3a503c7d0afa650a51d9e9eff06810ce33c76c9b0e2e86b667b5f7a7a77e95a8680312ae29ba3f48a437447b900b4869850c84485653ff7786cde5a496354da90b7216ef4b4c8e191c0cd14248a112dd08a8e0193821375ee53a81a53cb821af7b862bee86b755aaad50d3af55333a0e3b9aa5eb8803f89b98bce6af8c807195aaa4b02c4a41ab3ae5f301bbff51e92a5a40fdbe95cbfafea9cd012cd3182b6e64256a98a10a06d8b28919428544660e063542d920fb666ec7eb01c95b3aadfff8d9855c214ab9b9d039a3c807129246b633dea4760528aab3032460fdd10a0739adcd0db867f559bccf94b43749bd36b39cea05152c573ee4b27b8c108fc0b07f254f25b8ade60d5509337c2da2a3610a2de3859778b1f07d2c8b00b24fdbe824c52391c8c257ac744eb8d1780d9042de6afed2de67ce36aafdb3f750654c6d29609a83622091d17ef8235fa766d132a66d926d1b412c3281f3b1d590055c07bb0384c95eede784f0ce908725c9429b7f6c3c75cde9146db18c7177a4751fdd19c76179c
###
# (C) Tenable Network Security, Inc.
#
# @PREFERENCES@
###


include("compat.inc");

if(description)
{

  script_id(137233);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/04");

  script_name(english:"Datapower Settings");
  script_summary(english:"Set datapower preferences to perform security checks.");

  script_set_attribute(attribute:"synopsis", value:"Datapower settings." );
  script_set_attribute(attribute:"description", value: "This plugin just sets global variables for datapower");
  script_set_attribute(attribute:"solution", value:"n/a" );
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/08");
  script_set_attribute(attribute:"plugin_type", value:"settings");
  script_end_attributes();

  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_category(ACT_SETTINGS);

  exit(0);
}

include("global_settings.inc");

hashicorp  = script_get_preference("Datapower Enable Hashicorp : ");

if (!isnull(hashicorp))
{
  replace_kb_item(name:"Host/Datapower/Hashicorp", value:hashicorp);
  cert       = script_get_preference_file_location("Datapower Client Certificate : ");
  key        = script_get_preference_file_location("Datapower Private Key : ");
  passphrase = script_get_preference("Datapower Private Key Passphrase : ");
  header_key = script_get_preference("Datapower Custom Header Key : ");
  header_value = script_get_preference("Datapower Custom Header Value : ");
  if (!isnull(cert)) replace_kb_item(name:"Secret/Datapower/cert", value:cert);
  if (!isnull(key)) replace_kb_item(name:"Secret/Datapower/key", value:key);
  if (!isnull(passphrase)) replace_kb_item(name:"Secret/Datapower/passphrase", value:passphrase);
  if (!isnull(header_key)) replace_kb_item(name:"Secret/Datapower/headerkey", value:header_key);
  if (!isnull(header_value)) replace_kb_item(name:"Secret/Datapower/headervalue", value:header_value);
}
