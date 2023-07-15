#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(86322);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/06");

  script_cve_id("CVE-2002-0664");
  script_bugtraq_id(5101);

  script_name(english:"IBM Domino ZMerge Database Security Bypass");

  script_set_attribute(attribute:"synopsis", value:
"A remote database can be accessed without credentials.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Domino (formerly IBM Lotus Domino) running on the
remote host is affected by a security bypass vulnerability due to
insufficient access control list (ACL) settings on the administration
databases for ZMerge. An unauthenticated, remote attacker can exploit
this issue to disclose configuration information about the IBM Domino
server installation or possibly to gain manager level access.

Note that this plugin may report Domino databases without ZMerge, if 
the databases are found to be non-password protected.");
  # https://www.ibm.com/developerworks/lotus/library/dominowebserver-security/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?06aa671b");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2002/Sep/51");
  script_set_attribute(attribute:"solution", value:
"Verify all of the ACLs for the available databases.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute: "cvss_score_source", value: "CVE-2002-0664");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/domino");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

get_kb_item_or_exit("www/domino");

if (!thorough_tests)
{
  dbs = make_list(
    "admin4.nsf",
    "log.nsf",
    "names.nsf",
    "reports.nsf",
    "webadmin.nsf"
  );
}

else
{
  dbs = make_list(
    "account.nsf",
    "accounts.nsf",
    "admin4.nsf",
    "agentrunner.nsf",
    "AgentRunner.nsf",
    "archive/a_domlog.nsf",
    "archive/l_domlog.nsf",
    "bookmark.nsf",
    "books.nsf",
    "busytime.nsf",
    "calendar.nsf",
    "catalog.nsf",
    "cersvr.nsf",
    "certlog.nsf",
    "certsrv.nsf",
    "collect4.nsf",
    "cpa.nsf",
    "database.nsf",
    "db.nsf",
    "dbdirman.nsf",
    "decsadm.nsf",
    "default.nsf",
    "doladmin.nsf",
    "domcfg.nsf",
    "domguide.nsf",
    "domino.nsf",
    "domlog.nsf",
    "events4.nsf",
    "group.nsf",
    "groups.nsf",
    "hidden.nsf",
    "iNotes/Forms5.nsf",
    "lccon.nsf",
    "ldap.nsf",
    "lndfr.nsf",
    "log.nsf",
    "loga4.nsf",
    "mab.nsf",
    "mail.box",
    "mail/admin.nsf",
    "mailw46.nsf",
    "mtabtbls.nsf",
    "name.nsf",
    "names.nsf",
    "nntppost.nsf",
    "notes.nsf",
    "ntsync4.nsf",
    "private.nsf",
    "products.nsf",
    "proghelp/KBCCV11.nsf",
    "public.nsf",
    "qstart.nsf",
    "quickstart/qstart50.nsf",
    "quickstart/wwsample.nsf",
    "reports.nsf",
    "sample/faqw46.nsf",
    "sample/framew46.nsf",
    "secret.nsf",
    "secure.nsf",
    "setup.nsf",
    "smtpibwq.nsf",
    "smtpobwq.nsf",
    "smtptbls.nsf",
    "software.nsf",
    "statmail.nsf",
    "statrep.nsf",
    "statsrep.nsf",
    "stats675.nsf",
    "user.nsf",
    "users.nsf",
    "webadmin.nsf",
    "welcome.nsf",
    "zmevladm.nsf"
  );
}

report_dbs = "";

foreach db (dbs)
{
  res = http_send_recv3(
    method : "GET",
    item   : "/" + db,
    port   : port,
    exit_on_fail : TRUE
  );

  if (
    "Please identify yourself" >< res[2] ||
    'type="password"' >< res[2] ||
    preg(pattern:"<title>server login</title>", string:res[2], icase:TRUE, multiline:TRUE) ||
    '_QuickPlaceLoginForm' >< res[2] ||
    "WWW-Authenticate" >< res[1]
  )
  {
     set_kb_item(name:'www/domino/'+port+'/db/password_protected', value:db);
  }
  else if (res[0] =~ "200 OK" && (db >< res[2]))
  {
    set_kb_item(name:'www/domino/' + port + '/db/anonymous_access', value:db);
    report_dbs += "  " + build_url(qs:"/"+db, port:port) + '\n';
  }
}

if (report_dbs)
{
  report =
    '\nNessus found the following IBM Domino databases that can be accessed' +
    '\nwithout credentials :\n' +
    '\n' + report_dbs + '\n';

  security_report_v4(
    port: port,
    severity: SECURITY_HOLE,
    extra: report
  );
}
else audit(AUDIT_LISTEN_NOT_VULN, "IBM Domino", port);
