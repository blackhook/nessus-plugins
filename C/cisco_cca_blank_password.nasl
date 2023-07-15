#TRUSTED 546fa013064cd7486da3fb35bd7011e59121e3be6dee63e0af2cbb29f9fc2e17fc7e046aab416baa0d6452bec865ea863f36890d7eea9309be1b76add9562ce34bc8952fce5020acfc4091cd50c31ad131fe68c4e432564addef38f5599366b0108b01c6273875428974e29a17c6b910e34f9d8c98c868dbfc0e57f411c4d58665e1ebee08327d1bee0835db1f607eaa423a921b34dcc764910bb3bc04c0cbd6237ff912d34976dd9cb9bc0d1df4f3433301142e25d56996cb871b3b6c9c06fb3fd196503082f0df0e0ed7e39ea52f26ca60ca9ed7ce05bba01460e2e564968198b8fede5ba2c76be2afb434f341051cf4919aab37c3aa6f8cb2b9c5fb6d88e5d1e1127ad650b3803a63745e0e1f31b5a9f33f46231b47081fff081f6715eada6808445f9c622f452a92f35a0c3e735abed06f97ae4902512bbfdc159cad2e2be22b5ca84da6b4562f9746fa661a44bb63759de6bc7bd3d11888aac40122bf43eb10bf259d9feeda913ed838fbd44c9e2dee4eb92a853995e9d781759aa25f48bd1aa9787db934bf4eb1dfa576b9915aad3c9e349f903d202c2cc3073136efcb8c69ddfad1e87452038e39321beacde4706976f222c24ad49977e45a85d1f48397b49f1ac37320f262a44aaa38ee89c9ddca0b5579a78732ef31c35fa3a6a80b577c42f78f1baa51318af105a4c9a7eb7446d0e496d755d9d4e0b267ab7d0aca
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(70940);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/11");

  script_cve_id("CVE-2013-5558");
  script_bugtraq_id(63552);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj17238");
  script_xref(name:"IAVA", value:"2013-A-0211");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20131106-tvxca");

  script_name(english:"Cisco TelePresence VX Clinical Assistant WIL-A Module Reboot Admin Password Removal");

  script_set_attribute(attribute:"synopsis", value:
"The remote system has an account with a blank password.");
  script_set_attribute(attribute:"description", value:
"Cisco TelePresence VX Clinical Assistant is affected by a password
reset vulnerability. The WIL-A module causes the administrative
password to be reset to a blank password every time the device is
rebooted.

This plugin attempts to authenticate to the device using the username
'admin' and a blank password over SSH. It does not attempt to obtain a
version number and does not fully validate that the remote host is a
Clinical Assistant device.");
  # https://threatpost.com/cisco-fixes-blank-admin-password-flaw-in-telepresence-product/102846/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab239f3c");
  script_set_attribute(attribute:"solution", value:
"Follow the manufacturer's instructions to upgrade to a firmware
version later than 1.20");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-5558");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_vx_clinical_assistant");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("default_account.inc");

checking_default_account_dont_report = TRUE;

enable_ssh_wrappers();
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_service(svc: "ssh", exit_on_fail:TRUE, default: 22);

if (!port)
  audit(AUDIT_NOT_DETECT, "ssh");

detect = check_account(login:"admin", password:"", port:port, svc:"ssh", cmd:"",
                     cmd_regex:'Welcome to \r\nCisco Codec Release ', noexec:TRUE,
                     nosh:TRUE, nosudo:TRUE);

if (!detect)
  audit(AUDIT_RESP_BAD, port, "keyboard authentication with a blank password");

if ('Welcome to \r\nCisco Codec Release ' >!< _login_text)
  audit(AUDIT_NOT_DETECT, "Cisco TelePresence");

security_report_v4(port:port, severity:SECURITY_HOLE, extra:default_account_report());
