#TRUSTED 17f45c6782ec1152b32ee5f33b82ef629cf3357255823e7ae69a06015706fc532d1735927090abd18ad8d75c3f15fe309f3c9522dd9da0566c8f658a982fefb296bc32df2ebdac3afd0db0d8510ae5e981d2c9043f46bdbfe4c8852676d5e10f35db5b049207bbc7ad6641b4941daf683e2b525ccb236b40bcd3d7172657ed0ffbe39f2327db43b78ad2ae440e15f592e81be6f78a60c42c0340a551c7dd4287e6f34a84c7f29a646faf59195c0dfae9d9d65f037a46d17be293728dc6e057e596cfee166f77893c4056a2ad05ffdf6010ae0d0bb75b2ec94ab6d0960de146f42b95c1f41d24c9702b3751461f3392872fb2c7b2a84260fb454affd547ee5ff660fb3beccf5c100d86b0cbcd37aa1b3facbeb3f71a277089ede7a3e1ab9e3ace261cfcfada55d1a8d97fc338e8a0bada6af8fc1f0539f0448b537cd66b1f176eac2c140b64abed90da353c3e5d6755fd09ecb5769e84d631b16a8d6e62e99a2e8f49e0e91ef7071e7768e2787fd007865c9194c7c6fc6c1b1158004fbae6051fe62286c9639bfe4e90ae53a8b24aab35e97bfb1123d96aa73dadc516155c10654da213a6c21e8eb7581094469e4d86522a750066a1440bb3a0682e3c8229ece6b9e60fa6a466975395b44977067225eded78202466e0e4c785f54ed0f750eb41670b42874058fd2c05e5e0f777b7ee2b0976fb925b6d80e545714ffb287ec3d8
#TRUST-RSA-SHA256 6f20f014dcf8a346255eea76a09a75d0bc989a3b30e7b101e15bbdce8ba2b0801fc8da9155387744dc33b073ff70e601f8dce6025e3b82a44105f710bb569655f6f13da34877a2265a72cc1fd64d33b8a765a5885f4e1dc6a8c80e859c60771150937add7927e6c1f381c8086451a9996f577c6921ce2625154077d923770c9e1c166c2240e66d42db8c1fc73ca79231f9cd4bc0167a952777a1354b63db73ea0d0ea4b46b0bd0981a6c51b7eab6938292b7aa7d95edf720b9e7dc2e01699a24691ce61a017d252a8fb3ec69975c0f4a310d85a4b6974ef1b2f0e66c6dd418567a982dcdbdcafdce0f7d9212824074faf92cb96e8c8adf63846d3ed31172d50dee66b3d5757d663b12e4803047326ab31c078b06bf5ced59fb2d94d34a30d95386b0c104aed59b6bbc8dbe662d8a4d815fe0d7efd987933a783bd57c08300de800358cddb83cd22fe2f72a660fa0868f7deb8df847d9daa525ca0798e5a1703e3d0e9cad667d439f53a5fd1969844976292ef2886f481a90e5ba605d7da952fa8a0b6b93cfaae7bee38e45f7fe87e4d986458f0a654a6f9958a0436202813de01c8c3783be9626efad19ca769054afbe5fbe8f9ace46253d499e7f6c4980a724c285426f08c4fc8f5e456cf08277340f745534afdadc8cf2d935b8c4bc143bbbc01494314d97319c0212028bba3294706bd8179f672fe7062acfdef998339a0b
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72390);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/21");

  script_cve_id("CVE-2013-4424");
  script_bugtraq_id(64365);
  script_xref(name:"RHSA", value:"2013:1843");

  script_name(english:"Red Hat JBoss Enterprise Application Platform 6.1.0 Security Update (RHSA-2013:1843)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of JBoss Enterprise Application Platform running on the
remote system is affected by multiple cross-site scripting flaws in
the GateIn Portal component. This could allow a remote attacker to
manipulate a logged in user into visiting a specially crafted URL,
thereby executing an arbitrary web script in the context of the user's
GateIn Portal session.");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-4424.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate JBoss Enterprise Application Platform 6.1.0
security update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4424");
  
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_enterprise_application_platform");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "jboss_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/JBoss/EAP");

  exit(0);
}

include("ssh_func.inc");
include("telnet_func.inc");
include("local_detection_nix.inc");
include("hostlevel_funcs.inc");
include("datetime.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

# We are only interested in Red Hat systems
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");

installs = get_kb_list_or_exit("Host/JBoss/EAP");

info_connect(exit_on_fail:TRUE);

info = "";
jboss = TRUE;
invalid_path = FALSE;

foreach var install (make_list(installs))
{
  match = eregmatch(string:install, pattern:"([^:]+):(.*)");

  if (!isnull(match))
  {
    ver = match[1];
    path = match[2];

    if (path =~ INJECTION_PATTERN)
    {
      invalid_path = TRUE;
      continue;
    }

    # check for install version = 6.1.0
    if (ver =~ "^6.1.0([^0-9]|$)")
    {
      # check that the target file exists
      cmd = 'test -f "$1$modules/system/layers/base/org/jboss/ejb-client/main/jboss-ejb-client-1.0.21.Final-redhat-1.jar" && echo FOUND';
      buf = ldnix::run_cmd_template_wrapper(template:cmd, args:[path]);
      if ( (buf) && ("FOUND" >< buf) )
      {
        # extract the needed line from the file
        cmd = 'unzip -p $1$modules/system/layers/base/org/jboss/ejb-client/main/jboss-ejb-client-1.0.21.Final-redhat-1.jar META-INF/MANIFEST.MF | grep "Build-Timestamp"';
        buf = ldnix::run_cmd_template_wrapper(template:cmd, args:[path]);
        if ( (buf) )
        {
          # parse the line into the needed date portions
          match = eregmatch(string:buf, pattern:"Build-Timestamp: [^,]+,\s+(\d+)\s+([A-Za-z]+)\s+(\d+)");

          if (!isnull(match))
          {
            day = match[1];
            month = month_num_by_name(match[2], base:1);
            year = match[3];

            # compare the dates to see if it is older than the patch
            if (ver_compare(ver:year+"."+month+"."+day, fix:"2013.11.27") < 0)
            {
              info += '\n' + '  Path    : ' + path+ '\n';
              info += '  Version : ' + ver + '\n';
            }
          }
        }
      }
    }
  }
}

if (info_t == INFO_SSH) ssh_close_connection();

errors = "";
if(invalid_path)
{
  errors = '\nResults may not be complete due to the following errors : ';
  errors += '\n  The path name: "' + path + '" contained invalid characters.';
}

# Report what we found.
if (info)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 3) s = 's of JBoss Enterprise Application Platform are';
    else s = ' of JBoss Enterprise Application Platform is';

    report =
      '\n' +
      'The following instance'+s+' out of date and\nshould be patched or upgraded as appropriate :\n' +
      info +
      '\n' + errors;

    security_warning(port:0, extra:report);
  }
  else security_warning(port:0);
}
else if ( (!info) && (jboss) )
{
  exit(0, "The JBoss Enterprise Application Platform version installed is not affected." + errors);
}
else audit(AUDIT_HOST_NOT, "affected");
