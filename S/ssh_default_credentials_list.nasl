#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106462);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"SSH Multiple Device Default Credentials");

  script_set_attribute(attribute:"synopsis", value:
"The remote system can be accessed with a default set of credentials.");
  script_set_attribute(attribute:"description", value:
"The remote device is a device that uses a set of publicly known, default
credentials. Knowing these, an attacker able to connect to the service
can gain control of the device.");
  script_set_attribute(attribute:"see_also", value:"https://www.urtech.ca/2011/12/default-passwords/");
  script_set_attribute(attribute:"solution", value:
"Log into the remote host and change the default login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 Tenable Network Security, Inc.");

  script_dependencies("account_check.nasl", "ssh_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ssh", 22);

  exit(0);
}


include("audit.inc");
include("default_account.inc");
include("global_settings.inc");


if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


creds = [['1234',            '1234'],
         ['11111',           'x-admin'],
         ['aaa',             'cascade'],
         ['admin',           'comcomcom'],
         ['admin',           'bintec'],
         ['admin',           'cisco'],
         ['admin',           'system'],
         ['admin',           'my_DEMARC'],
         ['admin',           'Ascend'],
         ['admin',           'admin123'],
         ['admin',           'noway'],
         ['admin',           'NetCache'],
         ['admin',           'setup'],
         ['admin',           'adslolitec'],
         ['admin',           'OCS'],
         ['admin',           'mu'],
         ['admin',           'microbusiness'],
         ['admin',           'rmnetlm'],
         ['admin',           'pwp'],
         ['admin',           'extendnet'],
         ['admin',           '2222'],
         ['admin',           'isee'],
         ['admin',           'asante'],
         ['admin',           'michelangelo'],
         ['admin',           'sysAdmin'],
         ['admin',           'atlantis'],
         ['admin',           'passwort'],
         ['admin',           'adslroot'],
         ['admin',           'leviton'],
         ['admin',           'giraff'],
         ['admin',           'kont2004'],
         ['admin',           'conexant'],
         ['admin2',          'changeme'],
         ['Administrator',   'changeme'],
         ['administrator',   'administrator'],
         ['Administrator',   'ganteng'],
         ['Administrator',   'smcadmin'],
         ['Administrator',   'password'],
         ['adminstat',       'OCS'],
         ['adminstrator',    'changeme'],
         ['adminttd',        'adminttd'],
         ['adminuser',       'OCS'],
         ['adminview',       'OCS'],
         ['ADMN',            'admn'],
         ['ADSL',            'expert03'],
         ['ADVMAIL',         'HPOFFICE DATA'],
         ['ADVMAIL',         'HP'],
         ['bciim',           'bciimpw'],
         ['bcim',            'bcimpw'],
         ['bcms',            'bcmspw'],
         ['bcnas',           'bcnaspw'],
         ['blue',            'bluepw'],
         ['browse',          'browsepw'],
         ['browse',          'looker'],
         ['cablemodem',      'robotics'],
         ['ccrusr',          'ccrusr'],
         ['cellit',          'cellit'],
         ['CISCO15',         'otbu+1'],
         ['cmaker',          'cmaker'],
         ['craft',           'crftpw'],
         ['craft',           'craft'],
         ['craft',           'craftpw'],
         ['CSG',             'SESAME'],
         ['cust',            'custpw'],
         ['dadmin',          'dadmin01'],
         ['davox',           'davox'],
         ['deskalt',         'password'],
         ['deskman',         'changeme'],
         ['desknorm',        'password'],
         ['deskres',         'password'],
         ['diag',            'danger'],
         ['disttech',        '4tas'],
         ['eng',             'engineer'],
         ['engmode',         'hawk201'],
         ['enquiry',         'enquirypw'],
         ['Factory',         '56789'],
         ['FIELD',           'SUPPORT'],
         ['FIELD',           'MGR'],
         ['FIELD',           'SERVICE'],
         ['FIELD',           'MANAGER'],
         ['FIELD',           'HPP187 SYS'],
         ['FIELD',           'LOTUS'],
         ['FIELD',           'HPWORD PUB'],
         ['FIELD',           'HPONLY'],
         ['GEN1',            'gen1'],
         ['GEN2',            'gen2'],
         ['HELLO',           'MANAGER.SYS'],
         ['HELLO',           'MGR.SYS'],
         ['HELLO',           'FIELD.SUPPORT'],
         ['HELLO',           'OP.OPERATOR'],
         ['helpdesk',        'OCS'],
         ['hsa',             'hsadb'],
         ['hscroot',         'abc123'],
         ['HTTP',            'HTTP'],
         ['images',          'images'],
         ['inads',           'indspw'],
         ['inads',           'inads'],
         ['init',            'initpw'],
         ['install',         'secret'],
         ['intermec',        'intermec'],
         ['IntraStack',      'Asante'],
         ['IntraSwitch',     'Asante'],
         ['l2',              'l2'],
         ['l3',              'l3'],
         ['locate',          'locatepw'],
         ['login',           'admin'],
         ['lp',              'lp'],
         ['m1122',           'm1122'],
         ['MAIL',            'MAIL'],
         ['MAIL',            'REMOTE'],
         ['MAIL',            'TELESUP'],
         ['MAIL',            'HPOFFICE'],
         ['MAIL',            'MPE'],
         ['maint',           'maintpw'],
         ['maint',           'rwmaint'],
         ['maint',           'maint'],
         ['maint',           'ntacdmax'],
         ['manager',         'manager'],
         ['manager',         'friend'],
         ['MANAGER',         'TCH'],
         ['MANAGER',         'SYS'],
         ['MANAGER',         'SECURITY'],
         ['MANAGER',         'ITF3000'],
         ['MANAGER',         'HPOFFICE'],
         ['MANAGER',         'COGNOS'],
         ['MANAGER',         'TELESUP'],
         ['manuf',           'xxyyzz'],
         ['mediator',        'mediator'],
         ['MGR',             'HPP187'],
         ['MGR',             'HPP189'],
         ['MGR',             'HPP196'],
         ['MGR',             'INTX3'],
         ['MGR',             'ITF3000'],
         ['MGR',             'NETBASE'],
         ['MGR',             'REGO'],
         ['MGR',             'RJE'],
         ['MGR',             'CONV'],
         ['MGR',             'SYS'],
         ['MGR',             'CAROLIAN'],
         ['MGR',             'VESOFT'],
         ['MGR',             'XLSERVER'],
         ['MGR',             'SECURITY'],
         ['MGR',             'TELESUP'],
         ['MGR',             'HPDESK'],
         ['MGR',             'CCC'],
         ['MGR',             'CNAS'],
         ['MGR',             'WORD'],
         ['MGR',             'COGNOS'],
         ['MGR',             'ROBELLE'],
         ['MGR',             'HPOFFICE'],
         ['MGR',             'HPONLY'],
         ['MICRO',           'RSX'],
         ['mlusr',           'mlusr'],
         ['monitor',         'monitor'],
         ['NAU',             'NAU'],
         ['netman',          'netman'],
         ['netrangr',        'attack'],
         ['netscreen',       'netscreen'],
         ['NETWORK',         'NETWORK'],
         ['NICONEX',         'NICONEX'],
         ['nms',             'nmspw'],
         ['op',              'op'],
         ['op',              'operator'],
         ['operator',        'operator'],
         ['OPERATOR',        'SYS'],
         ['OPERATOR',        'DISC'],
         ['OPERATOR',        'SYSTEM'],
         ['OPERATOR',        'SUPPORT'],
         ['OPERATOR',        'COGNOS'],
         ['operator',        '1234'],
         ['PBX',             'PBX'],
         ['PCUSER',          'SYS'],
         ['PFCUser',         '240653C9467E45'],
         ['poll',            'tech'],
         ['PRODDTA',         'PRODDTA'],
         ['radware',         'radware'],
         ['rcust',           'rcustpw'],
         ['readonly',        'lucenttech2'],
         ['readwrite',       'lucenttech1'],
         ['replicator',      'replicator'],
         ['RMUser1',         'password'],
         ['root',            'ascend'],
         ['root',            'fivranne'],
         ['root',            "Mau'dib"],
         ['root',            'attack'],
         ['root',            'davox'],
         ['root',            '3ep5w2u'],
         ['root',            'admin_1'],
         ['root',            'blender'],
         ['root',            'iDirect'],
         ['RSBCMON',         'SYS'],
         ['scmadmin',        'scmchangeme'],
         ['scout',           'scout'],
         ['security',        'security'],
         ['Service',         '5678'],
         ['setup',           'setup'],
         ['setup',           'changeme'],
         ['SPOOLMAN',        'HPOFFICE'],
         ['SSA',             'SSA'],
         ['storwatch',       'specialist'],
         ['stratacom',       'stratauser'],
         ['su',              'super'],
         ['super.super',     'master'],
         ['superman',        'talent'],
         ['support',         'supportpw'],
         ['Sweex',           'Mysweex'],
         ['SYSADM',          'sysadm'],
         ['sysadmin',        'PASS'],
         ['sysadmin',        'sysadmin'],
         ['SYSDBA',          'masterkey'],
         ['teacher',         'password'],
         ['tech',            'field'],
         ['telecom',         'telecom'],
         ['tellabs',         'tellabs#1'],
         ['temp1',           'password'],
         ['tiger',           'tiger123'],
         ['topicalt',        'password'],
         ['topicnorm',       'password'],
         ['topicres',        'password'],
         ['user',            'public'],
         ['user',            'password'],
         ['admin',           'cableroot'],
         ['vcr',             'NetVCR'],
         ['vt100',           'public'],
         ['wlse',            'wlsedb'],
         ['wlseuser',        'wlsepassword'],
         ['WP',              'HPOFFICE'],
         ['wradmin',         'trancell'],
         ['xd',              'xd'],
         ['ZXDSL',           'ZXDSL']];

affected = FALSE;
ssh_ports = get_service_port_list(svc: "ssh", default:22);
foreach port (ssh_ports)
{
  report = "";
  foreach cred (creds)
  {
    vuln = check_account(login:cred[0], password:cred[1], noexec:TRUE,
                         port:port,
                         svc:"ssh");
    if (vuln)
    {
      report += '\n  Login : ' + cred[0] +
                '\n  Pass  : ' + cred[1] +
                '\n';
      affected = TRUE;
      if (!thorough_tests) break;
    }
  }
  if (report)
  {
    report = '\n' + 'Nessus was able to gain access using the following credentials :' +
             '\n' +
             report + default_account_report(cmd:cmd);
    security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
  }
}

if(!affected) audit(AUDIT_HOST_NOT, "affected");
