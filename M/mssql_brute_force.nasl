#%NASL_MIN_LEVEL 70300
##
#
#             MSSQL Brute Forcer
#
# This script checks a SQL Server instance for common
# username and password combinations. If you know of a
# common/default account that is not listed, please
# submit it to:
#
#   plugins@digitaloffense.net
#          or
#   deraison@cvs.nessus.org
#
# System accounts with blank passwords are checked for in
# a separate plugin (mssql_blank_password.nasl). This plugin
# is geared towards accounts created by rushed admins or
# certain software installations.
#
# Changes by Tenable:
# - Lansweeper; CVSSv3 base score; cosmetic (2016/09/06).
# - Added KB setters; moved supplied_login_checks; added 's' to script_dependencie; updated "PC America Restaurant Pro Express" URLs (2018/03/07)
# - 'PC America Restaurant Pro Express' changed to 'PC America Restaurant Pro Express / Cash Register Express' - similar software by same maker.  (2018/03/28)
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10862);
  script_version("1.41");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"Microsoft SQL Server Default Credentials");

  script_set_attribute(attribute:"synopsis", value:
"Credentials for the remote database server can be discovered.");
  script_set_attribute(attribute:"description", value:
"The SQL Server has a common password for one or more accounts. These
accounts may be used to gain access to the records in the database or
even allow remote command execution.");
  # https://github.com/mubix/post-exploitation-wiki/blob/master/windows/mssql.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5bc966a");
  script_set_attribute(attribute:"solution", value:
"Choose a strong password for affected SQL Server accounts using default
credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:X/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on manual analysis");

  script_set_attribute(attribute:"plugin_publication_date", value:"2002/02/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2001-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mssqlserver_detect.nasl", "sybase_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/mssql", 1433);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

pkt_hdr = raw_string(
    0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
);


pkt_pt2 = raw_string (
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x61, 0x30, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x20, 0x18, 0x81, 0xb8, 0x2c, 0x08, 0x03,
    0x01, 0x06, 0x0a, 0x09, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x73, 0x71, 0x75, 0x65, 0x6c, 0x64, 0x61,
    0x20, 0x31, 0x2e, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00
);

pkt_pt3 = raw_string (
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x4d, 0x53, 0x44,
    0x42, 0x4c, 0x49, 0x42, 0x00, 0x00, 0x00, 0x07, 0x06, 0x00, 0x00,
    0x00, 0x00, 0x0d, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
);

pkt_lang = raw_string(
    0x02, 0x01, 0x00, 0x47, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x30, 0x30, 0x00, 0x00,
    0x00, 0x03, 0x00, 0x00, 0x00
);


function sql_recv(socket)
{
 local_var head, len_hi, len_lo, len, body;

 head = recv(socket:socket, length:4, min:4);
 if(strlen(head) < 4) return NULL;

 len_hi = 256 * ord(head[2]);
 len_lo = ord(head[3]);

 len = len_hi + len_lo;
 body = recv(socket:socket, length:len);
 return(head + body);
}

function make_sql_login_pkt (username, password)
{
    local_var ulen, plen, upad, ppad, ubuf, pbuf, nul, ublen, pblen, sql_packet;

    ulen = strlen(username);
    plen = strlen(password);

    upad = 30 - ulen;
    ppad = 30 - plen;

    ubuf = "";
    pbuf = "";

    nul = raw_string(0x00);


    if(ulen)
    {
        ublen = raw_string(ulen % 255);
    } else {
        ublen = raw_string(0x00);
    }


    if(plen)
    {
        pblen =  raw_string(plen % 255);
    } else {
        pblen = raw_string(0x00);
    }

    ubuf = username + crap(data:nul, length:upad);
    pbuf = password + crap(data:nul, length:ppad);

    sql_packet = pkt_hdr + ubuf + ublen + pbuf + pblen + pkt_pt2 + pblen + pbuf + pkt_pt3;

    return sql_packet;
}


user[0]="sa";        pass[0]="sa";
user[1]="sa";        pass[1]="password";
user[2]="sa";        pass[2]="administrator";
user[3]="sa";        pass[3]="admin";

user[4]="admin";     pass[4]="administrator";
user[5]="admin";     pass[5]="password";
user[6]="admin";     pass[6]="admin";

user[7]="probe";     pass[7]="probe";
user[8]="probe";     pass[8]="password";

user[9]="sql";       pass[9]="sql";
user[10]="sa";       pass[10]="sql";
user[11]="jirauser"; pass[11]="jirauser";

# From https://github.com/mubix/post-exploitation-wiki/blob/master/windows/mssql.md
user[11]="ELNAdmin";
pass[11]="ELNAdmin";
product[11]="BioAssay Enterprise";
product_link[11]="http://www.cambridgesoft.com/solutions/details/?fid=175";

user[12]="msi";
pass[12]="keyboa5";
doc[12]="http://www.solutionoferror.com/java/sql-server-2008-r2-connection-error-android-254573.asp";

user[13]="sa";
pass[13]="111";
product[13]="IntegraXor";
product_link[13]="http://www.integraxor.com/index.htm";
doc[13]="http://www.integraxor.com/forum/viewtopic.php?f=2&t=75&start=10";

user[14]="sa";
pass[14]="CambridgeSoft_SA";
product[14]="BioAssay Enterprise";
product_link[14]="http://www.cambridgesoft.com/solutions/details/?fid=175";

user[15]="sa";
pass[15]="Cod3p@l";
product_link[15]="http://codepal.net/";
doc[15]="http://codepalinspections.net/CPO%20Setup%20On%20Alien%20Servers.txt";

user[16]="sa";
pass[16]="DHLadmin@1";
product[16]="DHL EasyShip";
product_link[16]="http://www.dhl-usa.com/en/express/resource_center/advanced_shipping.html";
doc[16]="http://rayotter.com/dhl/HTA/Create_Shipper_and_Defaults.hta.txt";

user[17]="sa";
pass[17]="Hpdsdb000001";
product[17]="HP MFP Digital Sending Software";
doc[17]="http://h20566.www2.hp.com/portal/site/hpsc/template.PAGE/public/kb/docDisplay/?sp4ts.oid=5076216&spf_p.tpst=kbDocDisplay&spf_p.prp_kbDocDisplay=wsrp-navigationalState%3DdocId%253Demr_na-c02712353-3%257CdocLocale%253D%257CcalledBy%253D&javax.portlet.begCacheTok=com.vignette.cachetoken&javax.portlet.endCacheTok=com.vignette.cachetoken";

user[18]="sa";
pass[18]="PCAmerica";
product[18]="PC America Restaurant Pro Express";
product_link[18]="http://www.pcamerica.com/restaurant-point-of-sale-features";
doc[18]="http://www.fixya.com/support/t3995856-restaurant_pro_express_client";
pci_default_creds[18]="yes";

user[19]="sa";
pass[19]="SLXMa$t3r";
product[19]="Saleslogix Software";
product_link[19]="http://www.saleslogix.com/";

user[20]="sa";
pass[20]="SLXMaster";
product[20]="Saleslogix Software";
product_link[20]="http://www.saleslogix.com/";

user[21]="sa";
pass[21]="hpdss";
product[21]="HP MFP Digital Sending Software";
doc[21]="http://h20566.www2.hp.com/portal/site/hpsc/template.PAGE/public/kb/docDisplay/?sp4ts.oid=5076216&spf_p.tpst=kbDocDisplay&spf_p.prp_kbDocDisplay=wsrp-navigationalState%3DdocId%253Demr_na-c02712353-3%257CdocLocale%253D%257CcalledBy%253D&javax.portlet.begCacheTok=com.vignette.cachetoken&javax.portlet.endCacheTok=com.vignette.cachetoken";

user[22]="sa";
pass[22]="mypassword";
product[22]="Microsoft Lync Server Databases";
doc[22]="http://www.kaplansoft.com/tekivr/TekIVR-Lync.pdf";

user[23]="sa";
pass[23]="pcAmer1ca";
product[23]="PC America Restaurant Pro Express / Cash Register Express";
product_link[23]="http://www.pcamerica.com/";
doc[23]="http://www.nessus.org/u?bb0eb3be";
pci_default_creds[23]="yes";

user[24]="sa";
pass[24]="sage";
product[24]="Act!";
product_link[24]="http://www.act.com/";

user[25]="sa";
pass[25]="ActbySage1!";
product[25]="Act! Premium";
product_link[25]="http://www.act.com/products/act-premium/";
doc[25]="http://community.act.com/t5/Act-Premium/ACT-Premium-2008-sa-password/td-p/1710";

user[26]="sa";
pass[26]="t9AranuHA7";
product[26]="My Movies";
product_link[26]="http://www.mymovies.dk/products.aspx";
doc[26]="http://www.mymovies.dk/forum.aspx?g=posts&t=24514";

user[27]="sa";
pass[27]="SQL";

user[28]="lansweeperuser";
pass[28]="mysecretpassword0*";
product[28]="Lansweeper";
product_link[28]="http://www.lansweeper.com/";
doc[28]="http://www.lansweeper.com/kb/72/How-to-change-the-default-Lansweeper-database-password.html";

user[29]="lansweeperuser";
pass[29]="Mysecretpassword0*";
product[29]="Lansweeper";
product_link[29]="http://www.lansweeper.com/";
doc[29]="http://www.lansweeper.com/kb/72/How-to-change-the-default-Lansweeper-database-password.html";

info = "";
service_unknown = FALSE;

port = get_kb_item("Services/mssql");
if (!port) port = get_kb_item("Services/sybase");
if (!port)
{
  port = 1433;
  if (!service_is_unknown(port:port))
    audit(AUDIT_NOT_LISTEN, "Microsoft SQL Server", port);

  service_unknown = TRUE;
}
if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);


found = 0;
for(i=0;user[i];i=i+1)
{
  username = user[i];
  password = pass[i];

  soc = open_sock_tcp(port);
  if (!soc)
    audit(AUDIT_SOCK_FAIL, port);

  # this creates a variable called sql_packet
  sql_packet = make_sql_login_pkt(username:username, password:password);

  send(socket:soc, data:sql_packet);
  send(socket:soc, data:pkt_lang);

  r  = sql_recv(socket:soc);
  close(soc);

  if (
    strlen(r) > 10 &&
    ord(r[8]) == 0xE3
  )
  {
    info += '    Account     : ' + username + '\n' +
            '    Password    : ' + password;

    # Add product name if available
    if (!isnull(product[i]))
    {
      info += '\n    Product     : ' + product[i];
      set_kb_item(name:"mssql/product_database_port", value:port);
      set_kb_item(name:"mssql/"+port+"/database/product", value:product[i]);
      if ( !isnull(pci_default_creds[i]) && pci_default_creds[i] == 'yes' )
      {
        set_kb_item(name:"PCI/pos_default_creds/"+port+"/product", value:product[i]);
        set_kb_item(name:"PCI/pos_default_creds/"+product[i]+"/username", value:username);
        set_kb_item(name:"PCI/pos_default_creds/"+product[i]+"/password", value:password);
        set_kb_item(name:"PCI/pos_default_creds/"+product[i]+"/port", value:port);
      }
    }

    # Add product link if available
    if (!isnull(product_link[i]))
    {
      info += '\n    Product URL : ' + product_link[i];
      set_kb_item(name:"mssql/"+port+"/database/product_link", value:product_link[i]);
    }

    # Add user ID / pwd data link if available
    if (!isnull(doc[i]))
      info += '\n    Info URL    : ' + doc[i];

    info += '\n\n';
    found = found + 1;
  }
}

if (found)
{
  report =
    '\n' +
    'The following credentials were discovered for the remote SQL Server :\n'+
    '\n' +
    info;
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
{
  if (service_unknown) exit(0, "The service listening on port "+port+" is not affected.");
  else audit(AUDIT_LISTEN_NOT_VULN, "Microsoft SQL Server", port);
}
