#%NASL_MIN_LEVEL 70300
###
# (C) Tenable Network Security, Inc.
###

include('deprecated_nasl_level.inc');
include('compat.inc');
include('host_os.inc');

if (description)
{
  script_id(33850);
  script_version("1.287");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_xref(name:"IAVA", value:"0001-A-0502");
  script_xref(name:"IAVA", value:"0001-A-0648");

  script_name(english:"Unix Operating System Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"The operating system running on the remote host is no longer
supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Unix operating
system running on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of the Unix operating system that is currently
supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Default unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2008-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "ssh_get_info2.nasl");
  script_require_keys("Host/OS");

  exit(0);
}

global_var global_report, last_call_succeeded;

function report(txt)
{
  last_call_succeeded = 1;
  if ( strlen(txt) > 0 )
    global_report = global_report + '\n' + txt;
}

function report_and_exit()
{
  if ( strlen(global_report) > 0 )
  {
    security_hole(port: 0, extra: global_report);
    set_kb_item(name: 'Host/OS/obsolete', value: TRUE);
    set_kb_item(name: 'Host/OS/obsolete/text', value:global_report);
  }
  exit(0);
}

# Beware of version numbers like 2.5 / 2.5.1; if 2.5.1 is not obsolete
# and 2.5 is, check the version before calling this function.
function check(os, dates, latest, url, name, cpe_part, ver_pat, note)
{
  local_var k, r, c, ubuntu_distrib, eos_date, item, version, tmp_name;

  if(isnull(ver_pat))
    ver_pat = "[^0-9.]([0-9.]+)[^0-9]*$";

  item = pregmatch(pattern:ver_pat, string:os);
  if(!isnull(item) && !isnull(item[1]))
    version = item[1];
  else version = 'unknown';

  r = "";
  c = TRUE;
  foreach k (keys(dates))
  {
    if (k >< os)
    {
      if ('Ubuntu' >< os && !(get_kb_item('Host/Ubuntu/ESM')))
      {
        ubuntu_distrib = get_kb_item('Host/Ubuntu/distrib_description');
        if (!isnull(ubuntu_distrib) && ubuntu_distrib =~ "^Ubuntu [0-9\.]+( LTS)?$")
        {
          ubuntu_distrib = chomp(ubuntu_distrib);
          # If we were able to get the distribution description, and it looks like
          # a stable branch, make sure we only report if k is the same as the
          # distribution branch by setting c to FALSE.
          c = FALSE;
          if (
            # match non-LTS
            k == ubuntu_distrib ||
            # match LTS
            ubuntu_distrib =~ "^Ubuntu 8\.04($|[^0-9])" ||
            ubuntu_distrib =~ "^Ubuntu 10\.04($|[^0-9])" ||
            ubuntu_distrib =~ "^Ubuntu 12\.04($|[^0-9])" ||
            ubuntu_distrib =~ "^Ubuntu 14\.04($|[^0-9])" ||
            ubuntu_distrib =~ "^Ubuntu 16\.04($|[^0-9])"
          )
          {
            if (name && name >!< k) r = r + name + " ";
            tmp_name = r + k;
            r = r + k + ' support ended';
            if (dates[k]) r = r + ' on ' + dates[k];
            r = r + '.\n';
            if (latest) r = r + 'Upgrade to ' + latest + '.\n';
            if (url)  r = r + '\nFor more information, see : ' + url + '\n\n';

            register_unsupported_product(
              product_name:tmp_name, 
              cpe_class:CPE_CLASS_OS,
              cpe_base:cpe_part,
              version:version);
            report(txt: r);
          }
        }
      }
      if (c)
      {
        if (name && name >!< k) r = r + name + " ";

        eos_date = NULL;
        if (dates[k])
        {
          eos_date = dates[k];
          if ("extended" >< tolower(eos_date))
          {
            set_kb_item(
              name:"Host/OS/extended_support",
              value:r + k + ' support ends on ' + eos_date + '.'
            );
            exit(0, r+k+" is on extended support.");
          }
        }
        tmp_name = r + k;
        r =  r + k + ' support ended';
        if (eos_date) r = r + ' on ' +eos_date;
        r = r +'.\n';
        if (latest) r = r + 'Upgrade to ' + latest + '.\n';
        if (!empty_or_null(note)) r = r + '\n' + note + '\n';
        if (url)  r = r + '\nFor more information, see : ' + url + '\n\n';
        register_unsupported_product(
          product_name:tmp_name, 
          cpe_class:CPE_CLASS_OS,
          cpe_base:cpe_part, 
          version:version);
        report(txt: r);
      }
     }
  }
}

function check_instance()
{
  local_var v, os, os2, os3, os4, k, k2, v2, sap_flag, sles_ltss, v_ltss;

  last_call_succeeded = 0;
  os = _FCT_ANON_ARGS[0];

  #### Mandrake / Mandriva Linux ####
  # Defunct as of 2015-05-27
  # http://www.linuxtoday.com/infrastructure/2003100201126NWMDSS
  # http://www.mandriva.com/en/mandriva-product-lifetime-policy
  # http://www.mandriva.com/en/security/advisories

  v = make_array(
    "Mandriva Business Server 2", "2015-05-27", # OS DEFUNCT
    "Mandriva Business Server 1", "2015-05-27", # OS DEFUNCT
    "Mandriva Enterprise Server 5", "2014-06-16",
    "Mandriva Linux 2011",   "2013-02-28",
    "Mandriva Linux 2010.1", "2012-07-08",
    "Mandriva Linux 2010.0", "2012-11-03",
    "Mandriva Linux 2009.1", "2010-10-29",
    "Mandriva Linux 2009.0", "2011-10-15",
    "Mandriva Linux 2008.1", "2009-10-15",
    "Mandriva Linux 2008.0", "2010-10-09",
    "Mandriva Linux 2007.1", "2015-05-27", # OS DEFUNCT
    "Mandriva Linux 2007.0", "2008-04-11", # or later?
    "MDK2007.0",             "2008-04-11", # or later?
    "Mandriva Linux 2006",   "2007-04-11", # or later?
    "MDK2006",               "2007-04-11", # or later?
    "MDK10.2",               "2015-05-27", # OS DEFUNCT
    "MDK10.1",               "2006-02-22", # or later?
    "MDK10.0",               "2005-09-20", # or later?
    "MDK9.2",                "2005-03-15", # or later?
    "MDK9.1",                "2004-08-31", # or later?
    "MDK9.0",                "2004-03-31",
    "MDK8.2",                "2003-09-30",
    "MDK8.1",                "2003-03-31",
    "MDK8.0",                "2003-03-31",
    "MDK7.2",                "2003-03-31",
    "MDK7.1",                "2002-10-15", # also Corporate Server 1.0.1
    "MDK7.0",                "2001-04-18",
    "MDK6.1",                "2001-04-18",
    "MDK6",                  "2001-04-18",
    "MDK5",                  "2015-05-27" # OS DEFUNCT
    # Single Network Firewall 7.2 n/a June 1, 2003
    # Multi Network Firewall 8. n/a December 12, 2004
);

check(
  os: os,
  dates: v,
  url: "https://en.wikipedia.org/wiki/Mandriva",
  cpe_part: "mandriva:linux",
  ver_pat: "[^0-9.]([0-9.]+)$");

# Old Mandrake need to be tested *before* Red Hat.

os2 = get_kb_item("Host/etc/mandrake-release");
if (strlen(os2) == 0)
{
  os2 = get_kb_item("Host/etc/redhat-release");
  if ("Mandrake" >!< os2) os2 = NULL;
}

if (strlen(os2) > 0)
{
 foreach k (keys(v))
 {
   k2 = str_replace(find: "MDK", replace: "release ", string: k);
   v2[k2] = v[k];
 }
 check(
   os: os2,
   dates: v2,
   name: "Linux Mandrake",
   url: "https://en.wikipedia.org/wiki/Mandriva",
   cpe_part: "mandriva:linux");
}

#### Mageia ####

v = make_array(
  # "Mageia 7",   "2020-12-30",         # https://www.mageia.org/en/support/ & https://advisories.mageia.org/7.html
  "Mageia 6",   "2019-09-30",         # https://www.mageia.org/en/support/ & https://advisories.mageia.org/6.html
  "Mageia 5",   "2017-12-31",           # https://www.mageia.org/en/support/
  "Mageia 4",   "2015-09-19",           # https://www.mageia.org/en/support/
  "Mageia 3",   "2014-11-26",           # http://blog.mageia.org/en/2014/11/26/lets-say-goodbye-to-mageia-3/
  "Mageia 2",   "2013-11-22",           # http://blog.mageia.org/en/2013/11/21/farewell-mageia-2/
  "Mageia 1",   "2012-12-01"            # http://blog.mageia.org/en/2012/12/02/mageia-1-eol/
);

check(
  os: os,
  dates: v,
  latest: "Mageia 6",
  url: "http://www.mageia.org/en/support/",
  cpe_part: "mageia:linux");

#### Fedora Linux / old RedHat ####
# https://fedoraproject.org/wiki/End_of_life
v = make_array(
  "Fedora release 32",            "2021-05-25",   # https://lists.fedoraproject.org/archives/list/announce@lists.fedoraproject.org/thread/RPZQXPEV3L45YQV2HRBIQ5DQZ7GMP4X3/
  "Fedora release 31",            "2020-11-24",   # https://lists.fedoraproject.org/archives/list/announce@lists.fedoraproject.org/thread/NU5AENRUFG4XK5D34SJN5FZPLYMZF6ZQ/
  "Fedora release 30",            "2020-05-26",   # https://lists.fedoraproject.org/archives/list/announce@lists.fedoraproject.org/thread/7UTUFY7WEL6RTFRXJB75XAFH44Y6RPUC/
  "Fedora release 29",            "2019-11-30",   # https://lists.fedoraproject.org/archives/list/announce@lists.fedoraproject.org/thread/VUK3CJ5LO4ROUH3JTCDVHYAVVYAOCU62/
  "Fedora release 28",            "2019-05-28",   # https://lists.fedoraproject.org/archives/list/announce@lists.fedoraproject.org/thread/RKGVIOHNF4HYC2FXEG7VRHMG7ARXGGRA/
  "Fedora release 27",            "2018-11-30",   # https://lists.fedoraproject.org/archives/list/announce@lists.fedoraproject.org/thread/ZSXRUH7JFXQNYP6JOAFTAUMSTLV6VMGO/
  "Fedora release 26",            "2018-05-29",   # https://lists.fedoraproject.org/archives/list/announce@lists.fedoraproject.org/thread/XGG7GYUJN3VDA6HX4KJNFSKSQCGF2FMW/
  "Fedora release 25",            "2017-12-12",   # https://lists.fedoraproject.org/archives/list/announce@lists.fedoraproject.org/thread/5VPF4YTQEXIGMR24VX5IRFYKONNNAEYW/
  "Fedora release 24",            "2017-08-08",   # https://lists.fedoraproject.org/archives/list/announce@lists.fedoraproject.org/thread/6PN47DOWEMLTUGJ2HCWAMXWFZ32HSTSH/
  "Fedora release 23",            "2016-12-10",   # https://lists.fedoraproject.org/archives/list/announce@lists.fedoraproject.org/thread/OHFCBTYXAO6NBH5BZZI3VIMIIL2ODFP5/
  "Fedora release 22",            "2016-07-19",   # https://lists.fedoraproject.org/archives/list/announce@lists.fedoraproject.org/thread/4FBGGXFXRMU5GHT6OSSNOYVPMONZDWSD/
  "Fedora release 21",            "2015-12-01",   # https://lists.fedoraproject.org/pipermail/devel/2015-November/216679.html
  "Fedora release 20",            "2015-06-23",   # https://lists.fedoraproject.org/pipermail/announce/2015-May/003267.html
  "Fedora release 19",            "2015-01-06",   # https://lists.fedoraproject.org/pipermail/announce/2015-January/003248.html
  "Fedora release 18",            "2014-01-14",   # https://lists.fedoraproject.org/pipermail/announce/2014-January/003194.html
  "Fedora release 17",            "2013-07-30",   # https://lists.fedoraproject.org/pipermail/announce/2013-July/003177.html
  "Fedora release 16",            "2013-02-12",   # https://lists.fedoraproject.org/pipermail/announce/2013-February/003144.html
  "Fedora release 15",            "2012-06-26",   # https://lists.fedoraproject.org/pipermail/announce/2012-May/003078.html
  "Fedora release 14",            "2011-12-08",   # http://lists.fedoraproject.org/pipermail/announce/2011-November/003010.html
  "Fedora release 13",            "2011-06-24",   # https://lists.fedoraproject.org/pipermail/announce/2011-June/002979.html
  "Fedora release 12",            "2010-12-02",   # https://lists.fedoraproject.org/pipermail/announce/2010-December/002895.html
  "Fedora release 11",            "2010-06-25",    # https://lists.fedoraproject.org/pipermail/announce/2010-June/002830.html
  "Fedora release 10",            "2009-12-17",
  "Fedora release 9",             "2009-07-10",
  "Fedora release 8",             "2009-01-07",
  "Fedora release 7",             "2008-06-13",
  "Fedora Core release 6", "2007-12-07",
  "Fedora Core release 5", "2007-07-02",
  "Fedora Core release 4", "2006-08-07",
  "Fedora Core release 3", "2006-01-16",
  "Fedora Core release 2", "2005-04-11",
  "Fedora Core release 1", "2004-09-20" );

check(
  os: os,
  dates: v,
  latest: "Fedora 33 / 34",
  url: "https://fedoraproject.org/wiki/End_of_life",
  cpe_part:"fedoraproject:fedora_core");

v = make_array (
  "Red Hat Linux release 9", "2004-04-30",
  "release 8", "2004-01-15", # 8.0
  "release 7", "2004-01-15",
  "release 6", "",
  "release 5", "",
  "release 4", "",
  "release 3", "" );
# This won't work against old Red Hat currently.
os2 = get_kb_item("Host/etc/redhat-release");
if (os2 =~ '^(Red Hat Linux )?release ')
  check(
    os: os2,
    dates: v,
    name: "Red Hat Linux",
    latest: "Fedora 33 / 34",
    url: "https://fedoraproject.org/wiki/End_of_life",
    cpe_part: "redhat:enterprise_linux");

#### Redhat Enterprise Linux ####
# https://access.redhat.com/support/policy/updates/errata
v = make_array (
  # "Red Hat Enterprise Linux Server release 7",      "2024-06-30 (end of production phase)",
  "Red Hat Enterprise Linux release 8.4",        "2023-05-31",
  "Red Hat Enterprise Linux release 8.3",        "2022-04-30",
  "Red Hat Enterprise Linux release 8.2",        "2022-04-30",
  "Red Hat Enterprise Linux release 8.1",        "2022-04-30",
  "Red Hat Enterprise Linux release 8.0",        "2022-04-30",
  "Red Hat Enterprise Linux Server release 7.1", "2017-03-31",
  "Red Hat Enterprise Linux Client release 7.1", "2017-03-31",
  "Red Hat Enterprise Linux Server release 7.2", "2017-11-30",
  "Red Hat Enterprise Linux Client release 7.2", "2017-11-30",
  "Red Hat Enterprise Linux Server release 7.3", "2018-11-30",
  "Red Hat Enterprise Linux Client release 7.3", "2018-11-30",
  "Red Hat Enterprise Linux Server release 7.4", "2019-08-31",
  "Red Hat Enterprise Linux Client release 7.4", "2019-08-31",
  "Red Hat Enterprise Linux Server release 7.5", "2020-04-30",
  "Red Hat Enterprise Linux Client release 7.5", "2020-04-30",
  "Red Hat Enterprise Linux Server release 7.6", "2021-05-31",
  "Red Hat Enterprise Linux Client release 7.6", "2021-05-31",
  "Red Hat Enterprise Linux Server release 7.7", "2021-08-31",
  "Red Hat Enterprise Linux Client release 7.7", "2021-08-31",
  "Red Hat Enterprise Linux Server release 6", "2020-11-30",
  "Red Hat Enterprise Linux Client release 6", "2020-11-30",
  "Red Hat Enterprise Linux Server release 5", "2020-11-30",
  "Red Hat Enterprise Linux Client release 5", "2020-11-30",
  "Red Hat Enterprise Linux 4",                "2012-02-29",
  "Red Hat Enterprise Linux 3",                "2010-10-31",
  "Red Hat Enterprise Linux 2.1",              "2009-05-31"
);
var supported_sap_part, repo_complete, new_repo_list;
var rhel_arch = ['x86_64', 'ppc64le', 's390x'];
var check_sap_repo_kb = get_kb_list("Host/RedHat/repo-list/*");

if (!empty_or_null(check_sap_repo_kb))
{
  foreach var arch (rhel_arch)
  {
    supported_sap_part =
    [
      'rhel-8-for-' + arch + '-sap-solutions-rpms', 'rhel-8-for-' + arch + '-sap-solutions-eus-rpms', 'rhel-8-for-' + arch + '-sap-solutions-e4s-rpms'
    ];

    foreach repo_complete (supported_sap_part)
    {
      if (pregmatch(pattern:repo_complete, string:check_sap_repo_kb))
      audit(AUDIT_HOST_NOT, "affected: supported SAP repository detected");
    }
  }
}

check(
  os     : os,
  dates  : v,
  latest : "Red Hat Enterprise Linux 8.6",
  url    : "https://access.redhat.com/support/policy/updates/errata/",
  cpe_part: "redhat:enterprise_linux"
  );


# http://www.redhat.com/security/updates/errata/
#
# os looks like
# "Red Hat Enterprise Linux ES release 4 (Nahant)"
#

# nb: per http://www.redhat.com/products/enterprise-linux-add-ons/extended-lifecycle-support/
#     and https://access.redhat.com/support/policy/updates/errata/, security updates will be
#     available through March 31, 2017 (RHEL 4).

v = make_array (
  "Red Hat Enterprise Linux AS release 5",      "2020-11-30",
  "Red Hat Enterprise Linux ES release 5",      "2020-11-30",
  "Red Hat Enterprise Linux WS release 5",      "2020-11-30",

  "Red Hat Enterprise Linux AS release 4",      "2012-02-29",
  "Red Hat Enterprise Linux ES release 4",      "2012-02-29",
  "Red Hat Enterprise Linux WS release 4",      "2012-02-29",

  "Red Hat Enterprise Linux AS release 3",      "2010-10-31",
  "Red Hat Enterprise Linux ES release 3",      "2010-10-31",
  "Red Hat Enterprise Linux WS release 3",      "2010-10-31",

  "Red Hat Enterprise Linux AS 2.1",            "2009-05-31",
  "Red Hat Enterprise Linux ES 2.1",            "2009-05-31",
  "Red Hat Enterprise Linux WS 2.1",            "2009-05-31",
  "Red Hat Linux Advanced Server 2.1",          "2009-05-31",
  "Red Hat Linux Advanced Workstation 2.1",     "2009-05-31"
);
os2 = get_kb_item("Host/etc/redhat-release");
if (strlen(os2) && os2 =~ '^Red Hat (Linux Advanced|Enterprise)')
  check(
    os     : os2,
    dates  : v,
    latest : "Red Hat Enterprise Linux 8 / 7",
    url    : "https://access.redhat.com/support/policy/updates/errata/",
    cpe_part: "redhat:enterprise_linux"
  );


#### CentOS ####
# https://wiki.centos.org/About/Product
# os looks like
# "CentOS release 3.6"

v = make_array (
  "CentOS Linux release 8",    "2021-12-31",
  # "CentOS release 7",    "2024-06-30",
  "CentOS release 6",    "2020-11-30",
  "CentOS release 5",    "2017-03-31",
  "CentOS release 4",    "2012-02-29",  # https://lists.centos.org/pipermail/centos-announce/2012-February/018462.html
  "CentOS release 3",    "2010-10-31",  # https://wiki.centos.org/FAQ/General#head-fe8a0be91ee3e7dea812e8694491e1dde5b75e6d
  "CentOS release 2",    "2009-05-31"
);
os2 = get_kb_item("Host/etc/redhat-release");
if (strlen(os2) && os2 =~ '^CentOS')
  check(
    os     : os2,
    dates  : v,
    latest : "CentOS Stream / 7",
    url    : "http://www.nessus.org/u?b549f616",
    cpe_part : "centos:centos"
  );
else
  check(
    os     : os,
    dates  : v,
    latest : "CentOS Stream / 7",
    url    : "http://www.nessus.org/u?b549f616",
    cpe_part : "centos:centos"
  );

# DR OS - based off CentOS and follows the same lifecycle policy
if (os =~ "^(Dell|Quest) DR[0-9]+")
{
  os2 = get_kb_item("Host/OS/HTTP");
  if (!empty_or_null(os2) && "CentOS" >< os2)
  {
    os += " (" + os2 + ")";
    check(
      os     : os,
      dates  : v,
      latest : "CentOS 8 / 7",
      note   : "Note that DR OS is based off CentOS and follows the same lifecycle policy.",
      url    : "http://www.nessus.org/u?e63bc1c5",
      cpe_part : "centos:centos"
    );
  }
}

#### Scientific Linux ####
# Policies seem to indicate that they will follow RedHat's dates for EOL/EOS.
v = make_array (
#  "Scientific Linux 7", "2024-06-30",
  "Scientific Linux 6", "2020-11-30", # https://scientificlinux.org/downloads/sl-versions/sl6/
  "Scientific Linux 5", "2017-03-31", # https://en.wikipedia.org/wiki/Scientific_Linux, https://scientificlinuxforum.org/index.php?showtopic=3590.
  "Scientific Linux 4", "2012-02-29", # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1202&L=SCIENTIFIC-LINUX-ANNOUNCE&P=R262&1=SCIENTIFIC-LINUX-ANNOUNCE&9=A&J=on&d=No+Match%3BMatch%3BMatches&z=4
  "Scientific Linux 3", "2010-10-10"
);
check(
  os     : os,
  dates  : v,
  latest : "Scientific Linux 7",
  url    : "https://www.scientificlinux.org/downloads/sl-versions/",
  cpe_part : "fermilab:scientific_linux"
  );


##
#  SuSE Linux
##

sap_flag = get_kb_item("Host/SuSE/SLES_SAP");
if (!empty_or_null(sap_flag) && sap_flag == 1)
{

  ##
  #  SuSE Linux Enterprise Server for SAP Applications
  ##
  #  nb: Per http://support.novell.com/inc/lifecycle/linux.html, once a
  #      new service pack for SuSE Linux is released, regular support ends
  #      6 months after.
  #
  #  nb: According to https://www.suse.com/support/programs/long-term-service-pack-support.html,
  #     extended support with LTSS option can extend support up to an additional 36 months.
  #
  #  https://www.suse.com/lifecycle/#suse-linux-enterprise-server-for-sap-applications-11
  #  https://www.suse.com/lifecycle/#suse-linux-enterprise-server-for-sap-applications-12
  #  https://www.suse.com/lifecycle/#suse-linux-enterprise-server-for-sap-applications-15
  #
  v = make_array(
    "SUSE Linux Enterprise Server for SAP Applications 15.0",  "2019-12-31 (end of regular support) / 2022-12-31 (end of ESPOS)",
    "SUSE Linux Enterprise Server for SAP Applications 12.4",  "2020-06-30 (end of regular support) / 2023-06-30 (end of ESPOS)",
    "SUSE Linux Enterprise Server for SAP Applications 12.3",  "2019-06-30 (end of regular support) / 2022-06-30 (end of ESPOS)",
    "SUSE Linux Enterprise Server for SAP Applications 12.2",  "2021-03-31 (end of ESPOS)",
    "SUSE Linux Enterprise Server for SAP Applications 12.1",  "2020-05-31 (end of ESPOS)",
    "SUSE Linux Enterprise Server for SAP Applications 12.0",  "2019-07-01 (end of ESPOS)",

    "SUSE Linux Enterprise Server for SAP Applications 11.4",  "2019-03-31 (end of regular support) / 2022-03-31 (LTSS option)",
    "SUSE Linux Enterprise Server for SAP Applications 11.3",  "2017-01-31 (end of regular support) / 2019-01-31 (LTSS option)",
    "SUSE Linux Enterprise Server for SAP Applications 11.2",  "2015-04-30 (end of regular support) / 2017-04-30 (LTSS option)",
    "SUSE Linux Enterprise Server for SAP Applications 11.1",  "2013-12-31 (end of regular support)",
    "SUSE Linux Enterprise Server for SAP Applications 11.0",  "2012-08-31 (end of regular support)"
  );

  os3 = get_kb_item("Host/SuSE/release");
  os4 = get_kb_item("Host/SuSE/patchlevel");
  if (os3 && preg(pattern:"^SLES_SAP[0-9]+$", string:os3) && !isnull(os4))
  {
    os = "SUSE Linux Enterprise Server for SAP Applications " + substr(os3, 8) + "." + os4;
    check(
      os: os,
      dates: v,
      latest: "SUSE Linux Enterprise for SAP Applications 11.4 / 12.x / 15.0",
      url: "https://www.suse.com/lifecycle/",
      cpe_part: "suse:sles_sap");
  }
}
else
{
  # SuSE Linux (not for SAP Applications)


  #### openSUSE ####
  #
  # nb: see also the SuSE Linux checks below.

  # Project Evergreen => community support. https://en.opensuse.org/Evergreen#Supported_distributions
  v = make_array(
    "openSUSE 15.3",  "2022-11-30",  # https://en.opensuse.org/openSUSE:Roadmap#Schedule_for_openSUSE_Leap_15.3
    "openSUSE 15.2",  "2022-01-04",  # https://en.opensuse.org/Lifetime#openSUSE_Leap
    "openSUSE 15.1",  "2021-02-02",    # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/WTRFFZBITYZ7AJP45W3EUMP3ODMX4BV7/
    "openSUSE 15.0",  "2019-11-30",
    "openSUSE 42.3",  "2019-06-30",    # https://en.opensuse.org/Lifetime
    "openSUSE 42.2",  "2018-01-26",    # https://lists.opensuse.org/opensuse-security-announce/2018-01/msg00103.html
    "openSUSE 42.1",  "2017-05-17",    # https://lists.opensuse.org/opensuse-security-announce/2017-05/msg00053.html
    "openSUSE 13.2",  "2017-01-17",    # https://lists.opensuse.org/opensuse-security-announce/2017-01/msg00033.html
    "openSUSE 13.1",  "2016-02-03 (end of official support) / 2016-11-01 (end of Project Evergreen Support)",    # http://lists.opensuse.org/opensuse-security-announce/2016-02/msg00004.html
    "openSUSE 12.3",  "2015-01-29",    # http://lists.opensuse.org/opensuse-security-announce/2015-02/msg00003.html
    "openSUSE 12.2",  "2014-01-27",    # http://lists.opensuse.org/opensuse-announce/2014-01/msg00000.html
    "openSUSE 12.1",  "2013-05-06",    # http://lists.opensuse.org/opensuse-announce/2013-06/msg00000.html
    "openSUSE 11.4",  "2012-11-05",    # http://lists.opensuse.org/opensuse-announce/2012-11/msg00000.html
    "openSUSE 11.3",  "2012-01-20",    # http://lists.opensuse.org/opensuse-announce/2012-01/msg00001.html
    "openSUSE 11.2",  "2011-05-12",    # http://en.opensuse.org/openSUSE:Evergreen_11.2
    "openSUSE 11.1",  "2011-01-14",    # Evergreen notes are incomplete for this ver. Listed at 'Support has stopped.'
    "openSUSE 11.0",  "2010-07-26",    # http://lists.opensuse.org/opensuse-security-announce/2010-07/msg00007.html
    "openSUSE 10.3",  "2009-10-31",    # http://lists.opensuse.org/opensuse-security-announce/2009-11/msg00008.html
    "openSUSE 10.2",  "2008-11-30",    # http://lists.opensuse.org/opensuse-security-announce/2008-12/msg00004.html
    "openSUSE 10.1",  "2008-05-31"     # http://lists.opensuse.org/opensuse-security-announce/2008-08/msg00004.html
  );

  check(
    os     : os,
    dates  : v,
    latest : "OpenSUSE 15.4",
    url    : "https://en.opensuse.org/Lifetime",
    cpe_part : "novell:opensuse"
  );

  #### SuSE Linux ####

  # self-support => no patch!
  # http://support.novell.com/lifecycle/lcSearchResults.jsp?sl=suse
  # SUSE Linux Enterprise Desktop 10  31 Jul 2011  31 Jul 2013
  # SUSE Linux Enterprise Point of Service 10  31 Jul 2011  31 Jul 2013
  # SUSE Linux Enterprise Real Time 10 SP1  31 Jul 2011  31 Jul 2013
  # SUSE Linux Enterprise Server 10  31 Jul 2011  31 Jul 2013
  # SUSE LINUX Enterprise Server 9  30 Jul 2009  30 Jul 2011
  # SUSE Linux Enterprise Thin Client 10  31 Jul 2011  31 Jul 2013

  # http://www.linuxtoday.com/infrastructure/2003100201126NWMDSS

  # nb: Per http://support.novell.com/inc/lifecycle/linux.html, once a
  #     new service pack for SuSE Linux is released, customers have 6
  #     months to move to move to the new release.
  # https://www.suse.com/lifecycle/

  v = make_array(
    "SuSE SLED1.0",         "2007-11-30", # ??
    "SuSE SLED8",           "2007-11-30", # ??
    # "SuSE Linux 15.0",      "TODO (SuSE Linux) / 2019-11-30 (openSUSE)",
    # "SuSE Linux 12.3",      "TODO (SuSE Linux) / 2015-01-29 (openSUSE)",
    "SuSE Linux 12.2",      "2018-03-31 (SuSE Linux) / 2014-01-27 (openSUSE)",
    "SuSE Linux 12.1",      "2017-05-31 (SuSE Linux) / 2013-05-06 (openSUSE)",
    "SuSE Linux 12.0",      "2016-06-30 (SuSE Linux)",
    "SuSE Linux 11.4",      "2016-03-31 (SuSE Linux) / 2012-11-05 (openSUSE)",
    "SuSE Linux 11.3",      "2016-01-31 (SuSE Linux) / 2012-01-20 (openSUSE)",
    "SuSE Linux 11.2",      "2014-01-31 (SuSE Linux) / 2011-05-12 (openSUSE)",
    "SuSE Linux 11.1",      "2012-08-31 (SuSE Linux) / 2011-01-14 (openSUSE)",
    "SuSE Linux 11.0",      "2010-12-31 (SuSE Linux) / 2010-07-26 (openSUSE)",      # http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5085390.html / http://lists.opensuse.org/opensuse-security-announce/2010-07/msg00007.html
    "SuSE Linux 10.3",      "2011-11-21 (SuSE Linux) / 2009-10-31 (openSUSE)",      # nb: http://lists.opensuse.org/opensuse-security-announce/2011-11/msg00026.html / http://lists.opensuse.org/opensuse-security-announce/2009-11/msg00008.html
    "SuSE Linux 10.2",      "2010-03-30 (SuSE Linux) / 2008-11-30 (openSUSE)",      # nb: http://lists.opensuse.org/opensuse-security-announce/2009-10/msg00002.html / http://lists.opensuse.org/opensuse-security-announce/2008-12/msg00004.html
    "SuSE Linux 10.1",      "2008-11-30 (SuSE Linux) / 2008-05-31 (openSUSE)",      # nb: http://lists.opensuse.org/opensuse-security-announce/2008-10/msg00011.html  / http://lists.opensuse.org/opensuse-security-announce/2008-08/msg00004.html
    "SuSE 10.0",  "2007-12-20",
    "SuSE 9.3",   "2007-06-19",
    "SuSE 9",     "2007-06-19",
    "SuSE 8",     "2007-11-30",
    "SuSE 7.2",   "2003-10-01",
    "SuSE 7",     "2003-10-01"
  );

  check(
    os: os,
    dates: v,
    latest: "OpenSUSE 15.0 / SUSE Linux Enterprise 12.3",
    url: "https://www.microfocus.com/lifecycle/",
    cpe_part: "suse:suse_linux");

  v = make_array(
    "SUSE LINUX Openexchange Server 4.0", "2007-10-14",
    "SUSE LINUX Openexchange Server 4.1", "2007-11-10",
    "SUSE LINUX Retail Solution 8", "2007-11-30",
    "SUSE LINUX Standard Server 8", "2007-11-30" );
  # This wouldn't work against the normalized names
  os2 = get_kb_item("Host/etc/suse-release");
  if (os2)
    check(
      os: os2,
      dates: v,
      latest: "OpenSUSE 15.0 / SUSE Linux Enterprise 12.3",
      url: "https://www.microfocus.com/lifecycle/",
      cpe_part: "suse:suse_linux" );



  ##
  #  SuSE Linux Enterprise Server / Desktop
  ##
  # nb: Per http://support.novell.com/inc/lifecycle/linux.html, once a
  #     new service pack for SuSE Linux is released, regular support ends
  #     6 months after.
  #
  # nb: According to https://www.suse.com/support/programs/long-term-service-pack-support.html,
  #     extended support with LTSS option can extend support up to an additional 36 months.
  v = make_array(
    # Dates for SUSE Enterprise Linux 15
    # https://www.suse.com/lifecycle/#suse-linux-enterprise-server-15
    "SUSE Linux Enterprise 15.3",  "2022-12-31 (end of regular support) / 2025-12-31 (LTSS option)",
    "SUSE Linux Enterprise 15.2",  "2021-12-31 (end of regular support) / 2024-12-31 (LTSS option)",
    "SUSE Linux Enterprise 15.1",  "2021-01-31 (end of regular support) / 2024-01-31 (LTSS option)",
    "SUSE Linux Enterprise 15.0",  "2019-12-31 (end of regular support) / 2022-12-31 (LTSS option)", 
    # Dates for SUSE Enterprise Linux 12
    # https://www.suse.com/lifecycle/#suse-linux-enterprise-server-12
    #"SUSE Linux Enterprise 12.5",  "2024-10-31 (end of regular support) / 2027-10-31 (LTSS option)",
    "SUSE Linux Enterprise 12.4",  "2020-06-30 (end of regular support) / 2023-06-30 (LTSS option)",
    "SUSE Linux Enterprise 12.3",  "2019-06-30 (end of regular support) / 2022-06-30 (LTSS option)",
    "SUSE Linux Enterprise 12.2",  "2018-03-31 (end of regular support) / 2021-03-31 (LTSS option)",
    "SUSE Linux Enterprise 12.1",  "2017-05-31 (end of regular support) / 2020-05-31 (LTSS option)",
    "SUSE Linux Enterprise 12.0",  "2016-06-30 (end of regular support) / 2019-07-01 (LTSS option)",
    "SUSE Linux Enterprise 11.4",  "2019-03-31 (end of regular support) / 2022-03-31 (LTSS option)",
    "SUSE Linux Enterprise 11.3",  "2016-01-31 (end of regular support) / 2019-01-30 (LTSS option)",  # https://www.suse.com/releasenotes/x86_64/SUSE-SLES/11-SP3/
    "SUSE Linux Enterprise 11.2",  "2014-01-31 (end of regular support) / 2017-01-30 (LTSS option)",  # https://www.novell.com/docrep/2013/04/long_term_service_pack_support_flyer.pdf
    "SUSE Linux Enterprise 11.1",  "2012-08-31 (end of regular support) / 2015-08-31 (LTSS option)",  # https://www.novell.com/docrep/2013/04/long_term_service_pack_support_flyer.pdf
    "SUSE Linux Enterprise 11.0",  "2010-12-31 (end of regular support)",  # http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5085390.html / http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5085394.html / http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5085396.html
    "SUSE Linux Enterprise 10.4",  "2013-07-31 (end of regular support) / 2016-07-31 (LTSS option)",
    "SUSE Linux Enterprise 10.3",  "2011-11-21 (end of regular support) / 2014-11-21 (LTSS option)",  # http://lists.opensuse.org/opensuse-security-announce/2011-11/msg00026.html
    "SUSE Linux Enterprise 10.2",  "2010-03-30 (regular support) / 2013-03-30 (LTSS option)",  # http://lists.opensuse.org/opensuse-security-announce/2009-10/msg00002.html
    "SUSE Linux Enterprise 10.1",  "2008-11-30 (regular support) / 2010-12-31 (LTSS option)",  # http://lists.opensuse.org/opensuse-security-announce/2008-10/msg00011.html
    "SUSE Linux Enterprise 10.0",  "",
    "SUSE Linux Enterprise 9.4",   "2011-08-31 (end of regular support) / 2014-08-31 (LTSS option)",  # http://support.novell.com/products/server/supported_packages/archive.html / http://lists.opensuse.org/opensuse-security-announce/2011-09/msg00003.html
    "SUSE Linux Enterprise 9.3",   "2008-02-29 (regular support) / 2011-03-01 (LTSS option)",  # http://support.novell.com/products/server/supported_packages/archive.html
    "SUSE Linux Enterprise 9.2",   "",
    "SUSE Linux Enterprise 9.1",   "",
    "SUSE Linux Enterprise 9.0",   "",
    "SUSE Linux Enterprise 8.0",   ""
  );
  # For LTSS activated SLES
  v_ltss = make_array(
    #"SUSE Linux Enterprise 15.3",  "2025-12-31 (LTSS option)",
    #"SUSE Linux Enterprise 15.2",  "2024-12-31 (LTSS option)",
    #"SUSE Linux Enterprise 15.1",  "2024-01-31 (LTSS option)",
    "SUSE Linux Enterprise 15.0",  "2022-12-31 (LTSS option)",
    #"SUSE Linux Enterprise 12.5",  "2027-10-31 (LTSS option)",
    "SUSE Linux Enterprise 12.4",  "2023-06-30 (LTSS option)",
    "SUSE Linux Enterprise 12.3",  "2022-06-30 (LTSS option)",
    "SUSE Linux Enterprise 12.2",  "2021-03-31 (LTSS option)",
    "SUSE Linux Enterprise 12.1",  "2020-05-31 (LTSS option)",
    "SUSE Linux Enterprise 12.0",  "2019-07-01 (LTSS option)",
    "SUSE Linux Enterprise 11.4",  "2022-03-31 (LTSS option)",
    "SUSE Linux Enterprise 11.3",  "2019-01-30 (LTSS option)",
    "SUSE Linux Enterprise 11.2",  "2017-01-30 (LTSS option)",
    "SUSE Linux Enterprise 11.1",  "2015-08-31 (LTSS option)",
    "SUSE Linux Enterprise 10.4",  "2016-07-31 (LTSS option)",
    "SUSE Linux Enterprise 10.3",  "2014-11-21 (LTSS option)",
    "SUSE Linux Enterprise 10.2",  "2013-03-30 (LTSS option)",
    "SUSE Linux Enterprise 10.1",  "2010-12-31 (LTSS option)",
    "SUSE Linux Enterprise 9.4",   "2014-08-31 (LTSS option)",
    "SUSE Linux Enterprise 9.3",   "2011-03-01 (LTSS option)"
  );
  os3 = get_kb_item("Host/SuSE/release");
  os4 = get_kb_item("Host/SuSE/patchlevel");
  sles_ltss = get_kb_item("Host/SuSE/LTSS");
  if ((empty_or_null(sles_ltss) || sles_ltss < 1) && os3 && preg(pattern:"^SLE[SD][0-9]+$", string:os3) && !isnull(os4))
  {
    os = "SUSE Linux Enterprise " + substr(os3, 4) + "." + os4;
    check(
      os: os,
      dates: v,
      latest: "SUSE Linux Enterprise 12.5 / 15.4",
      url: "https://www.suse.com/lifecycle/",
      cpe_part: "suse:suse_linux");
  }
  if ((!empty_or_null(sles_ltss) && sles_ltss == 1) && os3 && preg(pattern:"^SLE[SD][0-9]+$", string:os3) && !isnull(os4))
  {
    os = "SUSE Linux Enterprise " + substr(os3, 4) + "." + os4;
      check(
      os: os,
      dates: v_ltss,
      latest: "SUSE Linux Enterprise 12.5 LTSS / 15.x LTSS or migrate to a supported standard version",
      url: "https://www.suse.com/lifecycle/",
      cpe_part: "suse:suse_linux");
  }

} # matches else for SuSE (not for SAP Applications)


#### Gentoo Linux ####
# testing Gentoo does not make sense - but we may have a look at the profile
# See also gentoo_unmaintained_packages.nasl

#### Debian Linux ####
# https://wiki.debian.org/DebianReleases#Production_Releases
# https://wiki.debian.org/LTS
v = make_array(
  # Debian 11.x (Bullseye), current stable - https://wiki.debian.org/DebianBullseye
  # "Debian 11.0",   "2024-07-dd (end of regular support) / 2026-06-dd (end of long-term support for Bullseye-LTS)",

  # Debian 10.x (Buster), oldstable - https://wiki.debian.org/DebianBuster
  # End of LTS is taken from https://wiki.debian.org/LTS
  "Debian 10.13",  "2022-09-10 (end of regular support) / 2024-06-30 (end of long-term support for Buster-LTS)",
  "Debian 10.12",  "2022-09-10 (end of regular support) / 2024-06-30 (end of long-term support for Buster-LTS)",
  "Debian 10.11",  "2022-09-10 (end of regular support) / 2024-06-30 (end of long-term support for Buster-LTS)",
  "Debian 10.10",  "2022-09-10 (end of regular support) / 2024-06-30 (end of long-term support for Buster-LTS)",
  "Debian 10.9",   "2022-09-10 (end of regular support) / 2024-06-30 (end of long-term support for Buster-LTS)",
  "Debian 10.8",   "2022-09-10 (end of regular support) / 2024-06-30 (end of long-term support for Buster-LTS)",
  "Debian 10.7",   "2022-09-10 (end of regular support) / 2024-06-30 (end of long-term support for Buster-LTS)",
  "Debian 10.6",   "2022-09-10 (end of regular support) / 2024-06-30 (end of long-term support for Buster-LTS)",
  "Debian 10.5",   "2022-09-10 (end of regular support) / 2024-06-30 (end of long-term support for Buster-LTS)",
  "Debian 10.4",   "2022-09-10 (end of regular support) / 2024-06-30 (end of long-term support for Buster-LTS)",
  "Debian 10.3",   "2022-09-10 (end of regular support) / 2024-06-30 (end of long-term support for Buster-LTS)",
  "Debian 10.2",   "2022-09-10 (end of regular support) / 2024-06-30 (end of long-term support for Buster-LTS)",
  "Debian 10.1",   "2022-09-10 (end of regular support) / 2024-06-30 (end of long-term support for Buster-LTS)",
  "Debian 10.0",   "2022-09-10 (end of regular support) / 2024-06-30 (end of long-term support for Buster-LTS)",

  # Debian 9.x (Stetch), oldstable - https://wiki.debian.org/DebianStretch
  # End of LTS is taken from https://wiki.debian.org/LTS
  "Debian 9.13",  "2020-07-06 (end of regular support) / 2022-06-30 (end of long-term support for Stretch-LTS)",
  "Debian 9.12",  "2020-07-06 (end of regular support) / 2022-06-30 (end of long-term support for Stretch-LTS)",
  "Debian 9.11",  "2020-07-06 (end of regular support) / 2022-06-30 (end of long-term support for Stretch-LTS)",
  "Debian 9.10",  "2020-07-06 (end of regular support) / 2022-06-30 (end of long-term support for Stretch-LTS)",
  "Debian 9.9",   "2020-07-06 (end of regular support) / 2022-06-30 (end of long-term support for Stretch-LTS)",
  "Debian 9.8",   "2020-07-06 (end of regular support) / 2022-06-30 (end of long-term support for Stretch-LTS)",
  "Debian 9.7",   "2020-07-06 (end of regular support) / 2022-06-30 (end of long-term support for Stretch-LTS)",
  "Debian 9.6",   "2020-07-06 (end of regular support) / 2022-06-30 (end of long-term support for Stretch-LTS)",
  "Debian 9.5",   "2020-07-06 (end of regular support) / 2022-06-30 (end of long-term support for Stretch-LTS)",
  "Debian 9.4",   "2020-07-06 (end of regular support) / 2022-06-30 (end of long-term support for Stretch-LTS)",
  "Debian 9.3",   "2020-07-06 (end of regular support) / 2022-06-30 (end of long-term support for Stretch-LTS)",
  "Debian 9.2",   "2020-07-06 (end of regular support) / 2022-06-30 (end of long-term support for Stretch-LTS)",
  "Debian 9.1",   "2020-07-06 (end of regular support) / 2022-06-30 (end of long-term support for Stretch-LTS)",
  "Debian 9.0",   "2020-07-06 (end of regular support) / 2022-06-30 (end of long-term support for Stretch-LTS)",
 
  # Debain 8.x (Jessie), oldoldstable - https://wiki.debian.org/DebianJessie
  # EOL - https://www.debian.org/News/2020/20200709
  "Debian 8.11",  "2018-06-17 (end of regular support) / 2020-06-30 (end of long-term support for Jessie-LTS)",
  "Debian 8.10",  "2018-06-17 (end of regular support) / 2020-06-30 (end of long-term support for Jessie-LTS)",
  "Debian 8.9",   "2018-06-17 (end of regular support) / 2020-06-30 (end of long-term support for Jessie-LTS)",
  "Debian 8.8",   "2018-06-17 (end of regular support) / 2020-06-30 (end of long-term support for Jessie-LTS)",
  "Debian 8.7",   "2018-06-17 (end of regular support) / 2020-06-30 (end of long-term support for Jessie-LTS)",
  "Debian 8.6",   "2018-06-17 (end of regular support) / 2020-06-30 (end of long-term support for Jessie-LTS)",
  "Debian 8.5",   "2018-06-17 (end of regular support) / 2020-06-30 (end of long-term support for Jessie-LTS)",
  "Debian 8.4",   "2018-06-17 (end of regular support) / 2020-06-30 (end of long-term support for Jessie-LTS)",
  "Debian 8.3",   "2018-06-17 (end of regular support) / 2020-06-30 (end of long-term support for Jessie-LTS)",
  "Debian 8.2",   "2018-06-17 (end of regular support) / 2020-06-30 (end of long-term support for Jessie-LTS)",
  "Debian 8.1",   "2018-06-17 (end of regular support) / 2020-06-30 (end of long-term support for Jessie-LTS)",
  "Debian 8.0",   "2018-06-17 (end of regular support) / 2020-06-30 (end of long-term support for Jessie-LTS)",

  # Debian 7.x (Wheezy), obsolete stable - https://wiki.debian.org/DebianWheezy
  # EOL - https://www.debian.org/News/2018/20180601
  "Debian 7.11",  "2016-04-25 (end of regular support) / 2018-05-31 (end of long-term support for Wheezy-LTS)",
  "Debian 7.10",  "2016-04-25 (end of regular support) / 2018-05-31 (end of long-term support for Wheezy-LTS)",
  "Debian 7.9",   "2016-04-25 (end of regular support) / 2018-05-31 (end of long-term support for Wheezy-LTS)",
  "Debian 7.8",   "2016-04-25 (end of regular support) / 2018-05-31 (end of long-term support for Wheezy-LTS)",
  "Debian 7.7",   "2016-04-25 (end of regular support) / 2018-05-31 (end of long-term support for Wheezy-LTS)",
  "Debian 7.6",   "2016-04-25 (end of regular support) / 2018-05-31 (end of long-term support for Wheezy-LTS)",
  "Debian 7.5",   "2016-04-25 (end of regular support) / 2018-05-31 (end of long-term support for Wheezy-LTS)",
  "Debian 7.4",   "2016-04-25 (end of regular support) / 2018-05-31 (end of long-term support for Wheezy-LTS)",
  "Debian 7.3",   "2016-04-25 (end of regular support) / 2018-05-31 (end of long-term support for Wheezy-LTS)",
  "Debian 7.2",   "2016-04-25 (end of regular support) / 2018-05-31 (end of long-term support for Wheezy-LTS)",
  "Debian 7.1",   "2016-04-25 (end of regular support) / 2018-05-31 (end of long-term support for Wheezy-LTS)",
  "Debian 7.0",   "2016-04-25 (end of regular support) / 2018-05-31 (end of long-term support for Wheezy-LTS)",
  
  # Older than 7.x, all other obsolete stable
  "Debian 6.0",   "2014-05-31 (end of regular support) / 2016-02-29 (end of long-term support for Squeeze-LTS)",   # https://lists.debian.org/debian-announce/2014/msg00002.html
  "Debian 5.0",   "2012-02-06",   # http://lists.debian.org/debian-announce/2012/msg00001.html
  "Debian 4.0",   "2010-02-15",   # http://www.debian.org/News/2010/20100121
  "Debian 3.1",   "2008-03-31",
  "Debian 3.0",   "2006-06-30",
  "Debian 2.2",   "2003-06-30",
  "Debian 2.1",   "",
  "Debian 2.0",   "" );

check(
  os: os,
  dates: v,
  latest: 'Debian Linux 11.x ("Bullseye")',
  url: "http://www.debian.org/releases/",
  cpe_part: "debian:debian_linux");

#### Ubuntu Linux ####
# https://wiki.ubuntu.com/Releases
# https://help.ubuntu.com/community/UpgradeNotes#Unsupported%20(Obsolete)%20Versions
# http://en.wikipedia.org/wiki/Ubuntu_(Linux_distribution)
# http://www.ubuntu.com/products/whatisubuntu/serveredition/benefits/lifecycle
# Regular versions: Security patches are delivered for 18 months
# LTS versions : Security patches are delivered for 5 years (6.06, 8.04, 10.04...)

v = make_array(
  #"Ubuntu 21.04",       "2022-01-01 (end of maintenance) / xxxx-xx-xx (end of extended security maintenance)",   # https://wiki.ubuntu.com/Releases
  "Ubuntu 20.10",       "2021-07-31",   # https://wiki.ubuntu.com/Releases
 #"Ubuntu 20.04.2 LTS", "2025-04-30 (end of maintenance) / xxxx-xx-xx (end of extended security maintenance)",   # https://wiki.ubuntu.com/Releases
 #"Ubuntu 20.04.1 LTS", "2025-04-30 (end of maintenance) / xxxx-xx-xx (end of extended security maintenance)",   # https://wiki.ubuntu.com/Releases
 #"Ubuntu 20.04",       "2025-04-30 (end of maintenance) / 2030-04-30 (end of extended security maintenance)",   # https://wiki.ubuntu.com/Releases
  "Ubuntu 19.10",       "2020-07-30",   # https://wiki.ubuntu.com/Releases
 #"Ubuntu 18.04",       "2023-04-30 (end of maintenance) / 2028-04-30 (end of extended security maintenance)",   # https://wiki.ubuntu.com/Releases
  "Ubuntu 16.04",       "2021-04-30 (end of maintenance) / 2026-04-30 (end of extended security maintenance)", # https://wiki.ubuntu.com/Releases#:~:text=Ubuntu%2016.04%20ESM,April%202026
  "Ubuntu 19.04",       "2020-01-23",   # https://wiki.ubuntu.com/Releases
  "Ubuntu 18.10",       "2010-07-18",   # https://wiki.ubuntu.com/Releases
  "Ubuntu 17.10",       "2018-07-19",   # https://itsfoss.com/ubuntu-17-10-end-of-life/
  "Ubuntu 17.04",       "2018-01-13",   # https://lists.ubuntu.com/archives/ubuntu-announce/2018-January/000227.html
  "Ubuntu 16.10",       "2017-07-20",   # http://fridge.ubuntu.com/2017/07/20/ubuntu-16-10-yakkety-yak-end-of-life-reached-on-july-20-2017/
  "Ubuntu 15.10",       "2016-07-28",   # http://fridge.ubuntu.com/2016/07/07/ubuntu-15-10-wily-werewolf-reaches-end-of-life-on-july-28-2016/
  "Ubuntu 15.04",       "2016-02-04",   # https://lists.ubuntu.com/archives/ubuntu-security-announce/2016-February/003294.html
  "Ubuntu 14.10",       "2015-07-23",   # http://fridge.ubuntu.com/2015/07/03/ubuntu-14-10-utopic-unicorn-reaches-end-of-life-on-july-23-2015/
  "Ubuntu 14.04",       "2019-04-30 (end of maintenance) / 2024-04-30 (end of extended security maintenance)", # https://wiki.ubuntu.com/Releases#:~:text=Ubuntu%2014.04%20ESM,April%202024
  "Ubuntu 13.10",       "2014-07-17",   # https://lists.ubuntu.com/archives/ubuntu-security-announce/2014-July/002598.html
  "Ubuntu 13.04",       "2014-01-27",   # https://lists.ubuntu.com/archives/ubuntu-security-announce/2014-January/002382.html
  "Ubuntu 12.10",       "2014-05-16",   # https://lists.ubuntu.com/archives/ubuntu-security-announce/2014-May/002515.html
  "Ubuntu 12.04",       "2017-04-30",   # https://lists.ubuntu.com/archives/ubuntu-security-announce/2017-April/003833.html
  "Ubuntu 11.10",       "2013-05-09",   # https://lists.ubuntu.com/archives/ubuntu-announce/2013-March/000167.html
  "Ubuntu 11.04",       "2012-10-28",   # https://lists.ubuntu.com/archives/ubuntu-security-announce/2012-October/001882.html
  "Ubuntu 10.10",       "2012-04-10",   # https://lists.ubuntu.com/archives/ubuntu-announce/2012-April/000158.html
  "Ubuntu 10.04",       "2013-05-09 (Desktop) / 2015-04-30 (Server)", # https://lists.ubuntu.com/archives/ubuntu-announce/2013-March/000169.html
  "Ubuntu 9.10",        "2011-04-30",   # https://lists.ubuntu.com/archives/ubuntu-announce/2011-March/000142.html
  "Ubuntu 9.04",        "2010-10-23",   # https://lists.ubuntu.com/archives/ubuntu-announce/2010-September/000137.html
  "Ubuntu 8.10",        "2010-04-30",   # https://lists.ubuntu.com/archives/ubuntu-announce/2010-March/000130.html
  "Ubuntu 8.04",        "2011-05-12 (Desktop) / 2013-05-09 (Server)",   # https://lists.ubuntu.com/archives/ubuntu-announce/2011-April/000144.html
  "Ubuntu 7.10",        "2009-04-18",   # http://www.ubuntu.com/news/ubuntu-7.10-eol
  "Ubuntu 7.04",        "2008-10-19",   # https://lists.ubuntu.com/archives/ubuntu-announce/2008-September/000113.html
  "Ubuntu 6.10",        "2008-04-25",   # https://lists.ubuntu.com/archives/ubuntu-security-announce/2008-March/000680.html
  "Ubuntu 6.06.2 LTS",  "2011-06-01",    # https://lists.ubuntu.com/archives/ubuntu-announce/2011-June/000149.html
  "Ubuntu 6.06.1 LTS",  "2011-06-01",
  "Ubuntu 6.06 LTS",    "2011-06-01",
  "Ubuntu 6.06",        "2011-06-01",   # https://lists.ubuntu.com/archives/ubuntu-announce/2011-June/000149.html
  "Ubuntu 5.10",        "2007-04-13",
  "Ubuntu 5.04",        "2006-10-31",
  "Ubuntu 4.10",        "2006-04-30"
);
check(
  os: os,
  dates: v,
  latest: "Ubuntu 21.04 / LTS 20.04 / LTS 18.04",
  url: "https://wiki.ubuntu.com/Releases",
  cpe_part: "canonical:ubuntu_linux");

#### Slackware ####
v = make_array(
  # Per ftp://ftp.slackware.com/pub/slackware/slackware-12.0/ChangeLog.txt (see entry for June 14th, 2012):
  #
  # Effective August 1, 2012, security patches will no longer be     #
  # provided for the following versions of Slackware (which will all #
  # be more than 5 years old at that time):                          #
  # Slackware 8.1, 9.0, 9.1, 10.0, 10.1, 10.2, 11.0, 12.0.           #
  "Slackware 13.37",     "2018-07-05", # https://en.wikipedia.org/wiki/Slackware#Releases
  "Slackware 13.1",     "2018-07-05",  # https://en.wikipedia.org/wiki/Slackware#Releases
  "Slackware 13.0",     "2018-07-05",  # https://en.wikipedia.org/wiki/Slackware#Releases
  "Slackware 12.2",     "2012-12-09", # ftp://ftp.slackware.com/pub/slackware/slackware-12.1/ChangeLog.txt
  "Slackware 12.1",     "2013-12-09", # ftp://ftp.slackware.com/pub/slackware/slackware-12.1/ChangeLog.txt
  "Slackware 12.0",     "2012-08-01",
  "Slackware 11.0",     "2012-08-01",
  "Slackware 10.2",     "2012-08-01",
  "Slackware 10.1",     "2012-08-01",
  "Slackware 10.0",     "2012-08-01",
  "Slackware 9.1",      "2012-08-01",
  "Slackware 9.0",      "2012-08-01",
  "Slackware 8.1",      "2012-08-01"
);

check(
  os     : os,
  dates  : v,
  latest : 'Slackware 14.2',
  url    : "ftp://ftp.slackware.com/pub/slackware/slackware-12.0/ChangeLog.txt (see entry for June 14th, 2012)",
  cpe_part : "slackware:slackware_linux");

#### AIX ####
# http://en.wikipedia.org/wiki/AIX_operating_system

v = make_array(
  # "AIX 7.2", "2021-09-30 (end of standard support) / extended support is ongoing)", # https://www.ibm.com/support/pages/aix-support-lifecycle-information
  # "AIX 7.1", "2023-04-30 (end of standard support) / extended support is ongoing)", # https://www.ibm.com/support/pages/aix-support-lifecycle-information
  "AIX 6.1", "2017-04-30", # Only paid service is available https://www-01.ibm.com/common/ssi/cgi-bin/ssialias?htmlfid=MT303077WWEN
  "AIX 5.3", "2015-04-30",
  "AIX 5.2", "2009-04-30",
  "AIX 5.1", "2006-04-01",
  "AIX 4", "",
  "AIX 3", "");

check(
  os: os,
  dates: v,
  latest: "AIX 7.1 / 7.2",
  url: "http://www-01.ibm.com/software/support/aix/lifecycle/index.html",
  cpe_part: "ibm:aix");

#### HP-UX ####
# http://www.hp.com/softwarereleases/releases-media2/notices/0303.htm
# http://www.hp.com/softwarereleases/releases-media2/latest/06_08/0806_Update_letter.pdf
v = make_array(
  "HP-UX 10.20", "2003-07-01",
  "HP-UX 11.0", "2006-12-31", # (designated with VUF number B.11.00)
  "HP-UX B.11.00", "2006-12-31", # Not sure we store it like this
  # "HP-UX 11i??", "2003-03-01", # HP-UX 11i Version 1.5 for Itanium
  "HP-UX 7", "",
  "HP-UX 8", "",
  "HP-UX 9", "",
  "HP-UX 10", "2003-07-01" );

check(
  os: os,
  dates: v,
  latest: "HP-UX 11i V3",
  url: "https://www.hpe.com/global/softwarereleases/releases-media2/HPEredesign/pages/overview.html",
  cpe_part: "hp:hp-ux");

#### IRIX ####
v = make_array(
  "IRIX ", "2013-12-31");
check(
  os:os,
  dates:v,
  url:"https://web.archive.org/web/20150401201054/http://www.sgi.com/tech/irix/",
  cpe_part: "sgi:irix");

#### Solaris ####

# http://www.sun.com/service/eosl/solaris/solaris_vintage_eol_5.2005.xml
# http://web.archive.org/web/20060820024218/http://www.sun.com/service/eosl/solaris/solaris_vintage_eol_5.2005.xml
# http://www.sun.com/service/eosl/eosl_solaris.html

v = make_array(

  # nb: "For customers with a current support contract for the Oracle
  #     Solaris 8 release, new Severity 1 fixes and new security fixes
  #     will be available for the period of July 2012 - October 2014."
  #    from http://www.oracle.com/us/support/library/hardware-systems-support-policies-069182.pdf
  #
  # nb: from https://blogs.oracle.com/patch/entry/solaris_9_exiting_extended_support,
  #     "there will be a final patch release cycle in November for both
  #     Solaris 8 and Solaris 9..."
  # "Solaris 10", "2024-01-31", # https://blogs.oracle.com/solaris/great-news-about-extended-support-for-oracle-solaris-10-os
  "Solaris 9", "2014-10-31",
  "Solaris 8", "2014-10-31",
  "Solaris 7", "2005-08-15",
  "Solaris 2.6", "2003-07-23",
  "Solaris 2.5.1", "2002-09-22",
  "Solaris 2.5", "2000-12-27",
  "Solaris 2.4", "2000-09-30",
  "Solaris 2.3", "1999-06-01",
  "Solaris 2.2", "1996-05-01",
  "Solaris 2.1", "1996-04-15",
  "Solaris 2.0", "1996-01-01",
  "Solaris 1.4", "2000-09-30",
  # 1.3_U1 in fact
  "Solaris 1.3", "2000-09-30",
  # Solaris 1.1 & C 06/03/96
  "Solaris 1.2", "2000-01-06",
  "Solaris 1.1", "2000-01-06",
  "Solaris 1.0", "1999-09-30" );

check(
  os: os,
  dates: v,
  latest: "Solaris 11",
  url: "http://www.oracle.com/us/support/library/lifetime-support-hardware-301321.pdf",
  cpe_part: "sun:solaris");

#### FreeBSD ####
# http://www.auscert.org.au/render.html?it=9392
# http://www.daemonology.net/blog/2006-10-01-upcoming-freebsd-eols.html
# https://www.freebsd.org/security/unsupported.html
v = make_array(
  "FreeBSD 3",    "",
  "FreeBSD 4",    "2007-01-31",   # latest stable in the 4 series
  "FreeBSD 4.11", "2007-01-31",
  "FreeBSD 5",    "2008-05-31",   # latest stable in the 5 series
  "FreeBSD 5.3",  "2006-10-31",
  "FreeBSD 5.4",  "2006-10-31",
  "FreeBSD 5.5",  "2008-05-31",
  "FreeBSD 6",    "2010-11-30",   # latest stable in the 6 series
  "FreeBSD 6.0",  "2006-11-30",   # http://lists.freebsd.org/pipermail/freebsd-security/2010-November/005713.html
  "FreeBSD 6.1",  "2008-05-31",
  "FreeBSD 6.2",  "2008-05-31",
  "FreeBSD 6.3",  "2010-01-31",   # http://lists.freebsd.org/pipermail/freebsd-security/2009-October/005353.html
  "FreeBSD 6.4",  "2010-11-30",   # http://lists.freebsd.org/pipermail/freebsd-security/2010-November/005713.html
  "FreeBSD 7",    "2013-02-28",   # latest in the 7 series
  "FreeBSD 7.0",  "2009-04-30",   # http://lists.freebsd.org/pipermail/freebsd-security/2009-April/005205.html
  "FreeBSD 7.1",  "2011-02-28",   # http://lists.freebsd.org/pipermail/freebsd-security/2011-January/005771.html
  "FreeBSD 7.2",  "2010-06-30",   # http://lists.freebsd.org/pipermail/freebsd-announce/2010-June/001325.html
  "FreeBSD 7.3",  "2012-03-31",   # http://lists.freebsd.org/pipermail/freebsd-security/2012-March/006202.html
  "FreeBSD 7.4",  "2012-02-28",
  "FreeBSD 8",    "2015-08-01",   # latest stable in the 8 series
  "FreeBSD 8.0",  "2010-11-30",   # http://lists.freebsd.org/pipermail/freebsd-security/2010-November/005713.html
  "FreeBSD 8.1",  "2012-07-31",
  "FreeBSD 8.2",  "2012-07-31",
  "FreeBSD 8.3",  "2014-04-30",
  "FreeBSD 8.4",  "2015-08-01",   # https://lists.freebsd.org/pipermail/freebsd-announce/2015-August/001664.html
  "FreeBSD 9",    "2016-12-31",   # latest stable in the 9 series
  "FreeBSD 9.0",  "2013-03-31",
  "FreeBSD 9.1",  "2014-12-31",   # http://lists.freebsd.org/pipermail/freebsd-announce/2014-December/001615.html
  "FreeBSD 9.2",  "2014-12-31",   # http://lists.freebsd.org/pipermail/freebsd-announce/2014-December/001615.html
  "FreeBSD 9.3",  "2016-12-31",   # https://lists.freebsd.org/pipermail/freebsd-announce/2017-January/001779.html
  "FreeBSD 10.0", "2015-03-02",   # http://lists.freebsd.org/pipermail/freebsd-announce/2015-March/001630.html
  "FreeBSD 10.1", "2016-12-31",   # https://lists.freebsd.org/pipermail/freebsd-announce/2017-January/001779.html
  "FreeBSD 10.2", "2016-12-31",   # https://lists.freebsd.org/pipermail/freebsd-announce/2017-January/001779.html
  "FreeBSD 10.3", "2018-04-30",
  "FreeBSD 10.4", "2018-10-31", 
  "FreeBSD 11.0", "2017-11-30",   # https://lists.freebsd.org/pipermail/freebsd-announce/2017-December/001816.html
  "FreeBSD 11.1", "2018-09-30",
  "FreeBSD 11.2", "2019-10-31",    # https://www.freebsd.org/security/unsupported.html
  "FreeBSD 11.3", "2020-09-30",    # https://www.freebsd.org/security/unsupported.html
# "FreeBSD 11.4", "2021-09-30",    # https://www.freebsd.org/security/unsupported.html
  "FreeBSD 12.0", "2020-02-29",    # https://www.freebsd.org/security/unsupported.html
  "FreeBSD 12.1", "2021-01-31"    # https://www.freebsd.org/security/unsupported.html
);

os2 = get_kb_item("Host/FreeBSD/release");
if (os2)
  check(
    os: str_replace(string: os2, find: "FreeBSD-", replace: "FreeBSD "),
    dates: v,
    latest: "FreeBSD 11.4 / 12.2",
    url: "https://www.freebsd.org/security/",
    cpe_part: "freebsd:freebsd");
else
  check(
    os: os,
    dates: v,
    latest: "FreeBSD 11.4 / 12.2",
    url: "https://www.freebsd.org/security/",
    cpe_part: "freebsd:freebsd");

#### NetBSD ####
v = make_array(
  "NetBSD 7.0",  "2020-06-30", # http://www.netbsd.org/releases/formal.html
  "NetBSD 6.1",  "2015-11-09",          # https://blog.netbsd.org/tnf/entry/end_of_life_for_netbsd1
  "NetBSD 6.0",  "2015-11-09",          # https://blog.netbsd.org/tnf/entry/end_of_life_for_netbsd1
  "NetBSD 5.2",  "2015-11-09",          # https://blog.netbsd.org/tnf/entry/end_of_life_for_netbsd
  "NetBSD 5.1",  "2015-11-09",          # https://blog.netbsd.org/tnf/entry/end_of_life_for_netbsd
  "NetBSD 5.0",  "2015-11-09",          # https://blog.netbsd.org/tnf/entry/end_of_life_for_netbsd
  "NetBSD 4.0",  "2012-11-17",          # http://mail-index.netbsd.org/netbsd-announce/2012/10/27/msg000162.html
  "NetBSD 3.1",  "2009-05-29",          # http://mail-index.netbsd.org/netbsd-announce/2009/05/30/msg000066.html
  "NetBSD 3.0",  "2009-05-29",          # http://mail-index.netbsd.org/netbsd-announce/2009/05/30/msg000066.html
  "NetBSD 2.1",  "2008-04-30",          # http://mail-index.netbsd.org/netbsd-announce/2008/05/01/msg000025.html
  "NetBSD 2.0",  "2008-04-30",          # http://mail-index.netbsd.org/netbsd-announce/2008/05/01/msg000025.html
  "NetBSD 1.6",  "",
  "NetBSD 1.5",  "",
  "NetBSD 1.4",  "",
  "NetBSD 1.3",  "",
  "NetBSD 1.2",  "",
  "NetBSD 1.1",  "",
  "NetBSD 1.0",  "",
  "NetBSD 0.9",  "",
  "NetBSD 0.8",  ""
);

check(
  os     : os,
  dates  : v,
  latest : "NetBSD 8.1 / 9.1",
  url    : "http://www.netbsd.org/releases/formal.html",
  cpe_part : "netbsd:netbsd");

#### OpenBSD ####
# only the two most recent versions are actively supported
# according to http://www.openbsd.org/faq/faq5.html#Flavors
# https://en.wikipedia.org/wiki/OpenBSD_version_history

v = make_array(
# "OpenBSD 6.8", "2021-10-31", # still supported - https://endoflife.software/operating-systems/unix-like-bsd/openbsd
  "OpenBSD 6.7", "2021-05-31",
  "OpenBSD 6.6", "2020-10-18",
  "OpenBSD 6.5", "2020-05-19",
  "OpenBSD 6.4", "2019-10-17",
  "OpenBSD 6.3", "2019-05-03",
  "OpenBSD 6.2", "2018-10-18",
  "OpenBSD 6.1", "2018-04-15",
  "OpenBSD 6.0", "2017-10-09",
  "OpenBSD 5.9", "2017-04-11",
  "OpenBSD 5.8", "2016-09-01",
  "OpenBSD 5.7", "2015-03-29",
  "OpenBSD 5.6", "2015-10-18",
  "OpenBSD 5.5", "2015-04-30",
  "OpenBSD 5.4", "2014-11-01",
  "OpenBSD 5.3", "2014-05-01",
  "OpenBSD 5.2", "2013-11-01",
  "OpenBSD 5.1", "2013-05-01",
  "OpenBSD 5.0", "2012-11-01",
  "OpenBSD 4.9", "2012-05-01",
  "OpenBSD 4.8", "2011-11-01",
  "OpenBSD 4.7", "2011-05-01",
  "OpenBSD 4.6", "2010-11-01",
  "OpenBSD 4.5", "2010-05-19",
  "OpenBSD 4.4", "2009-10-18",
  "OpenBSD 4.3", "2009-05-01",
  "OpenBSD 4.2", "2008-11-01",
  "OpenBSD 4.1", "2008-06-30",
  "OpenBSD 4.0", "2007-11-01",
  "OpenBSD 3.9", "2007-06-30",
  "OpenBSD 3.8", "2006-11-13",
  "OpenBSD 3.7", "2006-05-18",
  "OpenBSD 3.6", "2006-10-30",
  "OpenBSD 3.5", "2005-06-30",
  "OpenBSD 3.4", "2004-10-30",
  "OpenBSD 3.3", "2004-05-05",
  "OpenBSD 3.2", "2003-11-04",
  "OpenBSD 3.1", "2003-06-01",
  "OpenBSD 3.0", "2002-12-01",
  "OpenBSD 2.9", "2002-06-01",
  "OpenBSD 2.", "",
  "OpenBSD 1.", "" );

check(
  os: os,
  dates: v,
  latest: "OpenBSD 6.9",
  url: "http://www.openbsd.org/security.html",
  cpe_part: "openbsd:openbsd");

#### Tru64 UNIX (and its earlier incarnations) ####
v = make_array(
  "Tru64 UNIX 5.1B-6", "2012-12-31 (end of standard support) / extended support is ongoing)",  # http://h30097.www3.hp.com/ees.html (for MPS w/o SE)
  "Tru64 UNIX 5.1B-5", "2012-12-31",  # http://h30097.www3.hp.com/tru64roadmap.pdf
  "Tru64 UNIX 5.1B-4", "2010-10-30",  # http://h30097.www3.hp.com/tru64roadmap.pdf
  "Tru64 UNIX 5.1B-3", "",
  "Tru64 UNIX 5.1B-2", "",
  "Tru64 UNIX 5.1B-1", "",
  # "Tru64 UNIX 5.1B",  we should flag this too but that might catch 5.1B-6
  "Tru64 UNIX 5.1A", "",
  # "Tru64 UNIX 5.1",  we should flag this too but that might catch 5.1B-6
  "Tru64 UNIX 5.0", "",
  "Tru64 UNIX 4.", "",
  "Digital UNIX", "",
  "DEC OSF/", ""
);
check(
  os:os,
  dates:v,
  url:"https://en.wikipedia.org/wiki/Tru64_UNIX",
  cpe_part: "hp:tru64");

#### Other very old distros ####
# uname:
# Linux CorelLinux 2.2.12 #1 SMP Tue Nov 9 14:11:25 EST 1999 i686 unknown

v = make_array("Corel Linux", "");
check(
  os: os,
  dates: v,
  url: "https://en.wikipedia.org/wiki/Corel_Linux",
  cpe_part: "corel:linux");

v = make_array("OpenLinux", "");
check(
  os: os,
  dates: v,
  url: "https://en.wikipedia.org/wiki/Caldera_OpenLinux",
  cpe_part: "caldera:openlinux");

v = make_array("Trustix", "2007-12-31");
check(
  os: os,
  dates: v,
  url: "https://en.wikipedia.org/wiki/Trustix",
  cpe_part: "trustix:secure_linux");


#### Mac OS X ####
v = make_array(
  "Mac OS X 10.0", "",
  "Mac OS X 10.1", "",
  "Mac OS X 10.2", "",
  "Mac OS X 10.3", "",
  "Mac OS X 10.4", "",
  "Mac OS X 10.5", "",
  "Mac OS X 10.6", "",
  "Mac OS X 10.7", "",
  "Mac OS X 10.8", "",
  "Mac OS X 10.9", "",
  "Mac OS X 10.10", "",
  "Mac OS X 10.11", "",
  "Mac OS X 10.12", "",
  "Mac OS X 10.13", ""
  # "Mac OS X 10.14", "", # osx supports the last 3 versions w/ patches
  # "Mac OS X 10.15", "", # https://support.apple.com/en-us/HT201222
  # "Mac OS x 11.4",""      # this constantly changes, increases
);
  local_var substring_match, version;
  local_var ver, tmp_name, url, latest, cpe_part, r, j;

  ver = pregmatch(pattern:"([0-9\.]+)", string:os);
  if (!isnull(ver)) ver = ver[0];

  substring_match = FALSE;
  local_var vuln = FALSE;
  foreach version (sort(keys(v)))
  {
    v2 = version;
    if (version >!< os) continue;
    version = pregmatch(pattern:"([0-9\.]+)", string:version);
    if(!isnull(version)) version = version[0];

    # If our version is in our list, we need to flag it
    if ((strlen(ver) == strlen(version)) && (ver == version))
    {
      vuln = TRUE;
      break;
    }
    # Compare subversions (ie if 10.3.9 is found)
    if (v2 >< os)
    {
      # 10.3.9 - 10.3 = .9
      j = (ver -version);
      if (j =~ "^\.[0-9]")
      {
        vuln = TRUE;
        break;
      }
    }
  }

  if (vuln)
  {
    url = "https://en.wikipedia.org/wiki/MacOS#Release_history";
    cpe_part = "apple:mac_os_x";
    latest = "Mac OS 11.4 (Big Sur) / 10.15 (Catalina) / 10.14 (Mojave)";

    r = 'Support for ' + os + ' has ended.\n';
    r += 'Upgrade to ' + latest + '.\n\n';
    r += 'Please note, Apple do not publish their End of Support dates. However, 
based on previous trends, it is assumed that only the last three versions 
of Mac OS X continue to receive security updates. For more information, 
please see : ' + url + '\n\n';

    register_unsupported_product(
      product_name : os,
      cpe_class    : CPE_CLASS_OS,
      cpe_base     : cpe_part,
      version      : version);
    report(txt: r);
  }

  # ========= VMware ESXi
  # ref: VMWare Full product Lifecycle Matrix
  # url: https://www.vmware.com/content/dam/digitalmarketing/vmware/en/pdf/support/product-lifecycle-matrix.pdf
  v = make_array(
    "VMware ESXi 1.", "",
    "VMware ESXi 2.", "",
    "VMware ESXi 3.", "2010-05-21",
    "VMware ESXi 4.", "2013-08-15",
    "VMware ESXi 5.", "2018-09-19" 
    # "VMware ESXi 6.", "2022-03-12", 
    # "VMware ESXi 6.5", "2023-11-15", 
    );

  check(
    os: ereg_replace(string:os, pattern:"VMware ESX Server \di ", replace:"VMware ESXi "),
    dates: v,
    latest: "VMware ESXi 6.7.0 build-10764712",
    url: "https://docs.vmware.com/en/VMware-vSphere/",
    cpe_part: "vmware:esxi");

  # ========= Oracle Linux
  local_var oracleVersion;
  local_var short_os = os;

  local_var isOracleLinux = get_kb_item("Host/OracleLinux");
  # is this oracle linux?
  if ( !isnull(isOracleLinux) )
  {
    # oracle linux, need to simplify mess of names
    oracleVersion = pregmatch( pattern:'[^0-9.]([0-9.]+)[^0-9.]*$', string:os );
    # can simplify?
    if ( !isnull(oracleVersion) )
    {
      # simplified, run check on Oracle Linux
      short_os = "Oracle Linux " + oracleVersion[1];
    }
    v = make_array(
      # https://www.oracle.com/a/ocom/docs/elsp-lifetime-069338.pdf
      "Oracle Linux 1", "",
      "Oracle Linux 2", "",
      "Oracle Linux 3", "2011-10-01",
      "Oracle Linux 4", "2013-02-01",
      "Oracle Linux 5", "2017-06-01",
      "Oracle Linux 6", "2021-03-01"
      # "Oracle Linux 7.", "2024-07-01",
      # "Oracle Linux 8.", "2029-07-01"
      );
    check(
      os: short_os,
      dates: v,
      # 7.x Release Notes : https://docs.oracle.com/en/operating-systems/oracle-linux/7/
      # 8.x Release Notes : https://docs.oracle.com/en/operating-systems/oracle-linux/8/
      latest: "Oracle Linux 7.9 / 8.4", 
      url: "https://yum.oracle.com/whatsnew.html",
      cpe_part: "oracle:linux");
  }

  # ========= Oracle VM Server
  # simplify mess of names
  local_var oracleVmVersion = pregmatch( pattern:'Oracle VM.*[^0-9.]([0-9.]+)', string:os );
  # was simplified?
  if ( !isnull(oracleVmVersion) )
  {
    # simplified, run check on Oracle VM Server
    short_os = "Oracle VM Server " + oracleVmVersion[1];
    v = make_array(
      "Oracle VM Server 1.", "",
      "Oracle VM Server 2.", "2015-11-01");
    check(
      os: short_os,
      dates: v,
      latest: "Oracle VM Server 3.4.6",
      url: "https://yum.oracle.com/whatsnew.html",
      cpe_part: "oracle:vm_server");
  }
}

os = get_kb_item("Host/OS");
if (host_os_id_uncertain()) os = NULL; # Avoid FP
if (os && '\n' >< os) os = split(os, keep:FALSE);
else if (strlen(os)) os = make_list(os);
else os = make_list();

# Handle very old distros
if (max_index(os) == 0 && max_index(keys(get_kb_list("Host/etc/*"))) == 0)
  exit(0);

rep = '';
var instance;

foreach instance (os)
{
 check_instance(instance);
 if (last_call_succeeded == 0) exit(0, "The remote OS is still supported.");
}

report_and_exit();
