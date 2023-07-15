#TRUSTED 1a2941cca02f735e74e3537300b521497d4dd4f4fce233bc0882b9c24d619125fbd0a08f8bd8c605901c535bb0809299002fa526d2b374e3a8b493231c8c7705532517775a3ea73ca2580b3e874d28c2204b614fc1c4927bf8395f705698241d7f8a045b5f5779409851fba8e4976e32a5b1b1217cdcdc73a5db01df0a75dda75f20771aaf51f8b53bfa1b6f5f893fde4669bc915262cf5b147d0796948e6280b7ba373b7724d2ee40d18aca24ec9080ba5c96c3be489d577ea320a19966c5373d03647211f259c176ffb7cfe7da941b434de081bdc46dcc0817ba88a3b7191f3e45cdee3276edbac3e3ad10189522645c7e63556991beb13a84d0497884d3aabe258c2320448e372f262319c77b246d2091976014c07eb232bc3781bb1bf6518b63c6b898dad514e9d96a76dc1fee63540b61b90961b49e63d38979047a56552a142e02d0c4b2f46e7dfc4922135f387ef77a1656e310689640a587f053a550bf0c3766cefcddfdf1cd963d308e353b964cd1de7b4bda67e37742ea911409b7a3766833db9012bbd712e8cd12d9b736a92180668f352a87a8c1d164b6513b0ab81445e22eb892b0e47176d605daaeba58617afc098f18d538f177bd0cba49bf438bc6dda2e91e9b3c5beb9ca9ee84c32629ff14703142b98a6a076d9c0a84217fa4cdb750fd5f7e5cfff87c5f731e911e8aea1bcd030e50c7c05e88935720c1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64258);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/11");

  script_bugtraq_id(57537);

  script_name(english:"Barracuda Appliances Default Credentials");
  script_summary(english:"Tries to login as product or emailswitch");

  script_set_attribute(attribute:"synopsis", value:"An account on the remote host uses a default password.");
  script_set_attribute(
    attribute:"description",
    value:
"The account 'product' or 'emailswitch' is using a default password.  A
remote, unauthenticated attacker could exploit this to log in as an
unprivileged user.  After logging in, an attacker can log into the local
MySQL server as root without a password.  Additionally, getting access
to a root shell is trivial. 

It is also likely that this host allows remote logins using the 'root',
'cluster', and 'remote' accounts using public key authentication, but
Nessus has not checked for those issues."
  );
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2013/Jan/220");
  script_set_attribute(attribute:"see_also", value:"https://www.barracuda.com/support#41");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Security Definition 2.0.5 or later.

Note that this fix does not disable access to the root, cluster, or
remote accounts."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score was rationalized for non-admin default device credentials.");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("default_account.inc");

checking_default_account_dont_report = TRUE;

enable_ssh_wrappers();
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

accounts = make_array(
  'product', 'pickle99',
  'emailswitch', 'pickle99'
);

# Get SSH port
port = get_service(svc:'ssh', exit_on_fail:TRUE, default:22);

foreach var user (keys(accounts))
{
  port = check_account(login:user, password:accounts[user], port:port, svc:"ssh");
  if (port)
  {
    security_report_v4(port:port, severity:SECURITY_HOLE, extra:default_account_report());
    exit(0);
  }
}

audit(AUDIT_LISTEN_NOT_VULN, 'SSH server', port);
