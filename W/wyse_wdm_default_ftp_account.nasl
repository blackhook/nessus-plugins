#TRUSTED 292b4638fcab225333284797be60d7cf9e81e53289e6826fdab6d29304df2248e9dc4423e498b1e850df6d54d5ef0e98bce8de939894142a736d88f4bd38494a7eff84a32ac8985a704279d2032e90da751b7b8492d9f83c78643afba0d27f8f5883a89a91b1ef8496bc5b8e0b291ae94e982078c3f65c9cc8b54500b9ef5e601b08ee0494f900da74aad326294e7e8155b847bfd74c9d15f1e0d6bb0a7a8900d68164d3561171d08f80fd7b80ba9ba971a2c11cdbb78a39a81c30664cb921ae70adca6350ccfce39f551b98dea2c8f9a7c4af42c033c9cafd250a82caafcd6815c5935899bed6b5996c9f89c5ceeab7f9188425bc75070ae8a8255bd92b9f86a3514efd86356fffc37e74a64b66dfec55d0f6a6ced62fd693762c18c6fe1c825779983c7b3e6f1fd54855fab068dfe92a3c92f1ea5375b1508862b6401a436b86812deff33fa239a1003a81d0ce0eb2306687036b8ec58f25150736f05dd8a4d5a30b1a4a56836e05f3a6a3df3a5170c182bb70dea856b3ab4d052ec600d11af2d49b6706ab08900eccd6af374179595f986c5bd267636099fffb2a18edc836736c643af6b5a3a094e1aac0b303b71d267e02f034496aa62c101bd0d6ab1c24b7ebc60cf6740f8807371aebceff8b550ba9f3e91bfefad260fd0d0b5cc483e3fb11ffefdfca9b81805cd05a69d3867f6e22684d5281d9a0c6869ff08a033ab9
###
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(40332);
 script_version("1.14");
 script_cvs_date("Date: 2018/10/10 14:50:53");
 
 script_name(english:"Wyse Device Manager Default FTP Account");
 script_summary(english:"Attempts to log in via FTP using credentials associated with Wyse Device Manager.");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server has an account that is protected with default
credentials." );
 script_set_attribute(attribute:"description", value:
"The remote FTP server has an account with a known username / password
combination, possibly created as part of an installation of Wyse
Device Manager. An attacker may be able to use this to gain
authenticated access to the system, which could allow for other
attacks against the affected application and host.");
 script_set_attribute(attribute:"solution", value:
"Change the password associated with the reported username.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"score from a more in depth analysis done by Tenable");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/20");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:dell:wyse_device_manager");
 script_set_attribute(attribute:"default_account", value:"true");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2009-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("DDI_FTP_Any_User_Login.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

#
# The script code starts here
#
include('audit.inc');
include('global_settings.inc');
include("misc_func.inc");
include('ftp_func.inc');

port = get_ftp_port(default: 419);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (get_kb_item("ftp/"+port+"/AnyUser"))
  audit(AUDIT_FTP_RANDOM_USER, port);

user   = "rapport";
passwd = "r@p8p0r+";

soc = ftp_open_and_authenticate( user:user, pass:passwd, port:port );
if (soc)
{
  ftp_close(socket:soc);

  if (report_verbosity > 0)
  {
    report =
     '\n' +
     'Nessus was able to log into the remote FTP server using the\n' +
     'following default credentials :\n' +
     'User     : ' + user + '\n' +
     'Password : ' + passwd + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}

audit(AUDIT_LISTEN_NOT_VULN, "FTP", port);
