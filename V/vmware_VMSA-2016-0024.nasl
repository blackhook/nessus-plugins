#TRUSTED 616e96dd41d7776713107ddf0b3e684e187e343ed07f2fb26e6829a73cb312eeed0a7983bd4742017dcbcfbaced8ffa48758115ca9e09f3b05af3bc0765b16931bf576ce5609afef15baf098b6b3d9c4d75173f23eef14bcb03cadbbbd5422af8573c8d9d551f4d56a791c860aa668f118598b360c81bf4d76e1b415033b6022a7e7d8ea86cdbd68593f685d566a55ad9edfda8c2ddf66d9c9ffb0186f0acf404358e6cb669b93dab46147fe9c4130b1e1e40704abaac728626dafb3996a96aa654c333dd31fcb198f7aa77db7e0bc6d28a29339a6803e9ebb1a71fc756386df367342a9b3cd2ce10a043e04b3140edc86cb8da11787890752dc74043ef1fca2fc267ebeca716d7fe724369b34a35a32fc4561ef31996de9039ae2b59703754b46127f009aac34bc49971227fc5b97414cd8ada09cd6fd47f64be80658b0cceda18b597c0e65cd955a0ab846f034b4c9ba83fd6e774a82c8e32f71d5e6e982c3386732df20b95b48b0f8f8c466caa34125d182c606a8c46f7e82af73b5221b0acdb36a2d3084b9c99adad6e1bb8c4a22cc5822ca73f5389e41ff5a62d007d2dd57144eea7fc35789514a05136bfc9959214c8a6b45e7475fabd711694edda0cabcc84f02cbf32e3158ce08070bbab507756e3da906f2090ef45018f14a8fd3a3772c18f4a6b8b5385a5fdc4b7b6776bd522327b78b350f6aae6c8752c51f984c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(96338);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2016-7456");
  script_bugtraq_id(94990);
  script_xref(name:"VMSA", value:"2015-0024");

  script_name(english:"VMware vSphere Data Protection Private SSH Key Authentication Bypass (VMSA-2016-0024)");
  script_summary(english:"Checks the version of VMware vSphere Data Protection.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization appliance installed on the remote host is affected by
an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vSphere Data Protection installed on the remote
host is 5.5.x / 5.8.x / 6.0.x / 6.1.x. It is, therefore, affected by
an authentication bypass vulnerability due to the use of an SSH
private key that has a known password and which is configured to allow
key-based authentication. A remote attacker can exploit this to gain
root login access via an SSH session.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2016-0024.html");
  # https://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=2147069
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e458ec43");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'VMware VDP Known SSH Key');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vsphere_data_protection");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/vSphere Data Protection/Version");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

app_name = "vSphere Data Protection";
version = get_kb_item_or_exit("Host/vSphere Data Protection/Version");
port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);
vuln = FALSE;
admin = FALSE;
root = FALSE;

dpnid = "-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQCWUMSv1kpW6ekyej2CaRNn4uX0YJ1xbzp7s0xXgevU+x5GueQS
mS+Y+DCvN7ea2MOupF9n77I2qVaLuCTZo1bUDWgHFAzc8BIRuxSa0/U9cVUxGA+u
+BkpuepaWGW4Vz5eHIbtCuffZXlRNcTDNrqDrJfKSgZW2EjBNB7vCgb1UwIVANlk
FYwGnfrXgyXiehj0V8p9Mut3AoGANktxdMoUnER7lVH1heIMq6lACWOfdbltEdwa
/Q7OeuZEY434C00AUsP2q6f9bYRCdOQUeSC5hEeqb7vgOe/3HN02GRH7sPZjfWHR
/snADZsWvz0TZQuybs8dEdGh/ezGhiItCINFkVg7NvSXx85dMVsB5N9Ju0gDsZxW
/d41VXYCgYBH0zIlb3lvioedyZj2mKF6fycnCZIeeDnL8wZtZPStRht6i4PFTCX1
Y/Ogw0L0bhuthOx+VTgICB87r0TmXElNUDLSncsxuw7pmHa669idUkv43CjeDkH0
kGFEHt4QA6/xw1Xq9oNpRJTo62ZsFmv0Pwp3uE7up8s0LW1O6fr+OwIVAKCJZ8nm
UwIdhEc9aU7sBDTFijP+
-----END DSA PRIVATE KEY-----";

dpn_pub = "ssh-dss AAAAB3NzaC1kc3MAAACBAJZQxK/WSlbp6TJ6PYJpE2fi5fRgnXFvOnuzTFeB69T7Hka55BKZL5j4MK83t5rYw66kX2fvsjapVou4JNmjVtQNaAcUDNzwEhG7FJrT9T1xVTEYD674GSm56lpYZbhXPl4chu0K599leVE1xMM2uoOsl8pKBlbYSME0Hu8KBvVTAAAAFQDZZBWMBp3614Ml4noY9FfKfTLrdwAAAIA2S3F0yhScRHuVUfWF4gyrqUAJY591uW0R3Br9Ds565kRjjfgLTQBSw/arp/1thEJ05BR5ILmER6pvu+A57/cc3TYZEfuw9mN9YdH+ycANmxa/PRNlC7Juzx0R0aH97MaGIi0Ig0WRWDs29JfHzl0xWwHk30m7SAOxnFb93jVVdgAAAIBH0zIlb3lvioedyZj2mKF6fycnCZIeeDnL8wZtZPStRht6i4PFTCX1Y/Ogw0L0bhuthOx+VTgICB87r0TmXElNUDLSncsxuw7pmHa669idUkv43CjeDkH0kGFEHt4QA6/xw1Xq9oNpRJTo62ZsFmv0Pwp3uE7up8s0LW1O6fr+Ow== dpn@dpn41s";

if (
    version =~ "^(5\.[58]|6\.[01])([^0-9]|$)"
    )
{
  sock_g = ssh_open_connection();
  if (! sock_g) audit(AUDIT_SOCK_FAIL, port);

  admin_authkeys = ssh_cmd(cmd:"cat /home/admin/.ssh/authorized_keys*");
  root_authkeys = ssh_cmd(cmd:"cat /root/.ssh/authorized_keys*");

  if(dpn_pub >< admin_authkeys) admin = TRUE;
  if(dpn_pub >< root_authkeys) root = TRUE;

  ssh_close_connection();
}

else
  audit(AUDIT_NOT_INST, app_name +" 5.5.x / 5.8.x / 6.0.x / 6.1.x ");

if (admin || root)
{
  report =
    '\nThe following users have a compromised ssh key in their authorized_keys file : \n\n';
  report +=   'Users : ';
  if(admin)
    report += '\n  - admin';
  if(root)
    report += '\n  - root';
    report +=
    '\n\nPrivate Key  : \n\n' + dpnid +
    '\n\nPublic Key   : \n' + dpn_pub + '\n';
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

