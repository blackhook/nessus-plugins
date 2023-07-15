#TRUSTED 67f468206fa039a5f65f49131265214ca09f40d233dca3fbea5ea07f45b461e69131594ff99572e9c5929fd4cee973a8390fc0b8919a3657f81daa54770be90dcf2c0fefb7355907c1c54f44b1033b57b03aaf2a6130432525b0c594cd9428bdb9fd73eab220fe8421d25b6f12ad0d9c7aaa88033aae37e9db5eaa9fa481530e96288e3e749859ff6acdac4f0572a268eaa89761d2fe2c6e650daaa689d5e54846bf24d4be04ce69df96eb31988189647f96e72f303863e4d9c4a3be726ad1bf3f7e131cb1a614bfa5f3f5f67d6be0342e0c2c6dc21a7bb40c0644f68f8ea4e6ddf083238cc4aede528299354da7fa59eabb0ce4a9a7c347b08d6daca658b3cf6f8ff0c834fa14b2148948369e8443c381e2ed7f1957d8e0cb706c50e30d127727705e87be88e82959ce23f8e4d70c7cf13a511834059ad4bc7c365924ed275551b10c48fb09b9c7b69fd52b35ac9e165acc2a4b2d1ffb6506fab32b600aebc333fc4e0ccc527061bcae8bc6d843eb826ff70ee3425c31ee42888ee25bc8cb7f2dd464a6dbe198a1d19ca2a3fe92cdb3fdcfc4af47878281c6a4b4ad79b6c5dec6650ddf1f8e2969947b2c17b0ebdb4276c68f6981e22f0b3a7f153ac59c0c4ccf908673a44f31028df73684e0253603033665f612168fe8964f5a5059c5949cfae78e7077f09c3faca568d33193e676aa2916ea4ee4bbeeaeed7cbaefca62e1
#%NASL_MIN_LEVEL 70300
###
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(18037);
  script_version("1.36");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2005-1078");
  script_bugtraq_id(13131);

  script_name(english:"XAMPP Default FTP Account");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server has an account that is protected with default
credentials.");
  script_set_attribute(attribute:"description", value:
"The remote FTP server has an account with a known username / password
combination that might have been configured when installing XAMPP. An
attacker may be able to use this to gain authenticated access to the
system, which could allow for other attacks against the affected
application and host.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2005/Apr/256");
  script_set_attribute(attribute:"solution", value:
"Modify the FTP password of the remote host.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-1078");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:xampp:apache_distribution");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
include('ftp_func.inc');

port = get_ftp_port(default:21);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (get_kb_item('ftp/'+port+'/AnyUser'))
  audit(AUDIT_FTP_RANDOM_USER, port);

i = 0;
users[i] = "nobody";
passes[i] = "xampp";

i++;
users[i] = "nobody";
passes[i] = "lampp";

# nb: this is the default in 1.4.13.
i++;
users[i] = "newuser";
passes[i] = "wampp";

info = "";
for (j=0; j<=i; j++)
{
  user = users[j];
  pass = passes[j];
  soc = ftp_open_and_authenticate( user:user, pass:pass, port:port );
  if(!soc) continue;
  info += '  - ' + user + '/' + pass + '\n';
  close(soc);
  if (!thorough_tests) break;
}


if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 1) s = "s";
    else s = "";

    report =
      '\n' +
      'Nessus uncovered the following set'+ s + ' of default credentials :\n' +
      info + '\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "FTP", port);
