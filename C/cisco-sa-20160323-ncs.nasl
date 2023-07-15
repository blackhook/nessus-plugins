#TRUSTED 9088c04de80ec920323c1dc525a48d5f89251ddfb4103cae4d2a3eacd4ed487d0cff96ce47fc47bd3f93662522b4d956d7b4e213c527ebb00669b44eaf0913e02cc3bda0468e8f34f390fce64ada2049f6420efc875ab70b2a9628e072dbf814d3bae8b12acff1fb2a35065280558be532a0e2d405fa264b743729b6b03bfc0fb8e3b14d117e608a39c0aab43b0ddb6c85db802292eed5b915913663b5f68d38ae133a616d971b3f8b1418da68e19a06593ea75dcb325735fd54ef005f674bac39f3dd960584a42ebc9826861391be051ebc08e6d9e2f02c7725f47ccdd4923afb3e47fc1d80ac3c61fa45bb7cc6c1e3a562f6b4e5d749cdec9c8122ca5f67a3cc288c5bb941c70380c8e0a96a71efb690044928ff90f59a6f0491524dc4a5cb601bc1a868e6a58ad239afd826f5e2db82239fdd0860adfb3e11436b3646e9a6bbf1309f02f2cb4b14d6a4931a7fdb68f84ef0d267b64db40fcf580926317101a26cc543fc43e12bc1fd289ff4b40b455c6dc43ae9ebcacac5399c461050d868b0d96ab00e701e2e2556161799b4836d597af860088f46be06e28c4b4a61782d735726dc5609adf0e16ac9d79b218bdbe1698a185aee77338c3355fcc8240e2df68de25507a142c65c184519c78b06a7aa669b2e94a7c07e986623aac68b294612d11d4bb8d489033eb806b0312e2a8263a17b50b346d5e80bb2480084dbec74
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90357);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2016-1366");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw75848");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-ncs");

  script_name(english:"Cisco IOS XR SCP and SFTP Modules DoS (cisco-sa-20160323-ncs)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XR software
running on the remote device is affected by a denial of service
vulnerability in the Secure Copy Protocol (SCP) and Secure FTP (SFTP)
modules due to insecure permissions on certain files. An
authenticated, remote attacker can exploit this to overwrite system
files, resulting in a denial of service.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-ncs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3fc8f969");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuw75848.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1366");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

cbi = "CSCuw75848";

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

# Since we cannot properly check the model, only run when paranoid
if (report_paranoia < 2) audit(AUDIT_PARANOID);

if( version =~ "^5\.0\.[01]([^0-9]|$)" ) flag = 1;
if( version =~ "^5\.2\.[1345]([^0-9]|$)" ) flag = 1;

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : ' + cbi +
      '\n  Installed release : ' + version +
      '\n';

    security_warning(port:port, extra:report + cisco_caveat(override));
  }
  else security_warning(port:port, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
