#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122157);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/22");

  script_name(english:"Unsupported linux kernel version detected in banner reporting (PCI-DSS check)");
  script_summary(english:"Checks banners for unsupported kernel levels");

  script_set_attribute(
    attribute:"synopsis",
    value:"The Linux kernel version reported in banners is no longer supported."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A service banner response from the remote host indicates a Linux 
kernel install at a level that may no longer be supported, where
kernel development and security patching has ceased.

This plugin only runs when 'Check for PCI-DSS compliance' is enabled
in the scan policy. It does not run if local security checks are
enabled. It runs off of self-reported kernel versions in banners."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.kernel.org/category/releases.html");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Linux_kernel");
  script_set_attribute(
    attribute:"solution",
    value:
"Update the version of the Linux kernel running on the system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported software.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Settings/PCI_DSS");
  script_exclude_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("kernel_cves.inc");
include("lists.inc");

if (!get_kb_item("Settings/PCI_DSS")) audit(AUDIT_PCI);
if (get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are enabled.");

unsupported_kernel_version = make_array();
unsupported_kernel_version["supported_levels"] = "3.16 / 4.4 / 4.9 / 4.14 / 4.19 / 5.0";
unsupported_kernel_version["0.01"]["eol_date"] = "1991-11-01";
unsupported_kernel_version["0.01"]["eol_url"] = "https://www.kernel.org/category/releases.html";
unsupported_kernel_version["0.1"]["eol_date"] = "1992-03-08";
unsupported_kernel_version["0.1"]["eol_url"] = "https://www.kernel.org/category/releases.html";
unsupported_kernel_version["0.95"]["eol_date"] = "1994-03-14";
unsupported_kernel_version["0.95"]["eol_url"] = "https://www.kernel.org/category/releases.html";
unsupported_kernel_version["1.0"]["eol_date"] = "1994-04-06";
unsupported_kernel_version["1.0"]["eol_url"] = "https://www.kernel.org/category/releases.html";
unsupported_kernel_version["1.1"]["eol_date"] = "1995-03-07";
unsupported_kernel_version["1.1"]["eol_url"] = "https://www.kernel.org/category/releases.html";
unsupported_kernel_version["1.2"]["eol_date"] = "1995-06-12";
unsupported_kernel_version["1.2"]["eol_url"] = "https://www.kernel.org/category/releases.html";
unsupported_kernel_version["1.3"]["eol_date"] = "1996-06-09";
unsupported_kernel_version["1.3"]["eol_url"] = "https://www.kernel.org/category/releases.html";
unsupported_kernel_version["2.0"]["eol_date"] = "1999-01-26";
unsupported_kernel_version["2.0"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/9901.2/1084.html";
unsupported_kernel_version["2.2"]["eol_date"] = "2005-01-13";
unsupported_kernel_version["2.2"]["eol_url"] = "https://web.archive.org/web/20070630014451/http://kerneltrap.org/node/4533";
unsupported_kernel_version["2.4"]["eol_date"] = "2011-12-31";
unsupported_kernel_version["2.4"]["eol_url"] = "https://lkml.org/lkml/2010/12/18/73";
unsupported_kernel_version["2.6"]["eol_date"] = "2004-12-24";
unsupported_kernel_version["2.6"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/0412.3/0072.html";
unsupported_kernel_version["2.6.11"]["eol_date"] = "2005-06-18";
unsupported_kernel_version["2.6.11"]["eol_url"] = "https://archive.is/20150228154849/http://lkml.iu.edu/hypermail/linux/kernel/0506.2/0404.html";
unsupported_kernel_version["2.6.12"]["eol_date"] = "2005-08-28";
unsupported_kernel_version["2.6.12"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/0508.3/1073.html";
unsupported_kernel_version["2.6.13"]["eol_date"] = "2005-12-15";
unsupported_kernel_version["2.6.13"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/0512.1/2520.html";
unsupported_kernel_version["2.6.14"]["eol_date"] = "2006-01-02";
unsupported_kernel_version["2.6.14"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/0601.0/0281.html";
unsupported_kernel_version["2.6.15"]["eol_date"] = "2006-03-28";
unsupported_kernel_version["2.6.15"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/0603.3/1141.html";
unsupported_kernel_version["2.6.16"]["eol_date"] = "2008-07-21";
unsupported_kernel_version["2.6.16"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/0807.2/2508.html";
unsupported_kernel_version["2.6.17"]["eol_date"] = "2006-10-16";
unsupported_kernel_version["2.6.17"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/0610.2/0295.html";
unsupported_kernel_version["2.6.18"]["eol_date"] = "2007-02-23";
unsupported_kernel_version["2.6.18"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/0702.2/3139.html";
unsupported_kernel_version["2.6.19"]["eol_date"] = "2007-03-03";
unsupported_kernel_version["2.6.19"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/0703.0/0965.html";
unsupported_kernel_version["2.6.20"]["eol_date"] = "2007-10-17";
unsupported_kernel_version["2.6.20"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/0710.2/0891.html";
unsupported_kernel_version["2.6.21"]["eol_date"] = "2007-08-04";
unsupported_kernel_version["2.6.21"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/0708.0/1438.html";
unsupported_kernel_version["2.6.22"]["eol_date"] = "2008-02-25";
unsupported_kernel_version["2.6.22"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/0802.3/0774.html";
unsupported_kernel_version["2.6.23"]["eol_date"] = "2008-02-25";
unsupported_kernel_version["2.6.23"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/0802.3/0772.html";
unsupported_kernel_version["2.6.24"]["eol_date"] = "2008-05-06";
unsupported_kernel_version["2.6.24"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/0805.0/3106.html";
unsupported_kernel_version["2.6.25"]["eol_date"] = "2008-11-10";
unsupported_kernel_version["2.6.25"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/0811.1/00748.html";
unsupported_kernel_version["2.6.26"]["eol_date"] = "2008-11-10";
unsupported_kernel_version["2.6.26"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/0811.1/00751.html";
unsupported_kernel_version["2.6.27"]["eol_date"] = "2012-03-17";
unsupported_kernel_version["2.6.27"]["eol_url"] = "https://lkml.org/lkml/2012/3/17/38";
unsupported_kernel_version["2.6.28"]["eol_date"] = "2009-05-02";
unsupported_kernel_version["2.6.28"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/0905.0/00587.html";
unsupported_kernel_version["2.6.29"]["eol_date"] = "2009-07-02";
unsupported_kernel_version["2.6.29"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/0907.0/01080.html";
unsupported_kernel_version["2.6.30"]["eol_date"] = "2009-10-05";
unsupported_kernel_version["2.6.30"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/0910.0/01918.html";
unsupported_kernel_version["2.6.31"]["eol_date"] = "2010-07-05";
unsupported_kernel_version["2.6.31"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/1007.0/01836.html";
unsupported_kernel_version["2.6.32"]["eol_date"] = "2016-03-12";
unsupported_kernel_version["2.6.32"]["eol_url"] = "https://lkml.org/lkml/2016/3/12/78";
unsupported_kernel_version["2.6.33"]["eol_date"] = "2011-11-07";
unsupported_kernel_version["2.6.33"]["eol_url"] = "https://lwn.net/Articles/466233/";
unsupported_kernel_version["2.6.34"]["eol_date"] = "2014-02-11";
unsupported_kernel_version["2.6.34"]["eol_url"] = "https://lkml.org/lkml/2014/2/11/368";
unsupported_kernel_version["2.6.35"]["eol_date"] = "2011-08-01";
unsupported_kernel_version["2.6.35"]["eol_url"] = "https://lkml.org/lkml/2011/8/1/324";
unsupported_kernel_version["2.6.36"]["eol_date"] = "2011-02-17";
unsupported_kernel_version["2.6.36"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/1102.2/01003.html";
unsupported_kernel_version["2.6.37"]["eol_date"] = "2011-03-27";
unsupported_kernel_version["2.6.37"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/1103.3/01699.html";
unsupported_kernel_version["2.6.38"]["eol_date"] = "2011-06-02";
unsupported_kernel_version["2.6.38"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/1106.0/01226.html";
unsupported_kernel_version["2.6.39"]["eol_date"] = "2011-08-03";
unsupported_kernel_version["2.6.39"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/1108.0/01203.html";
unsupported_kernel_version["3.0"]["eol_date"] = "2013-10-22";
unsupported_kernel_version["3.0"]["eol_url"] = "https://lkml.org/lkml/2013/10/22/125";
unsupported_kernel_version["3.1"]["eol_date"] = "2012-01-18";
unsupported_kernel_version["3.1"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/1201.2/01340.html";
unsupported_kernel_version["3.2"]["eol_date"] = "2018-06-01";
unsupported_kernel_version["3.2"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/1806.0/00251.html";
unsupported_kernel_version["3.3"]["eol_date"] = "2012-06-04";
unsupported_kernel_version["3.3"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/1206.0/01162.html";
unsupported_kernel_version["3.4"]["eol_date"] = "2016-10-26";
unsupported_kernel_version["3.4"]["eol_url"] = "https://www.spinics.net/lists/announce-kernel/msg01708.html";
unsupported_kernel_version["3.5"]["eol_date"] = "2012-10-12";
unsupported_kernel_version["3.5"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/1210.1/03204.html";
unsupported_kernel_version["3.6"]["eol_date"] = "2012-12-17";
unsupported_kernel_version["3.6"]["eol_url"] = "https://lkml.org/lkml/2012/12/17/353";
unsupported_kernel_version["3.7"]["eol_date"] = "2013-02-27";
unsupported_kernel_version["3.7"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/1302.3/01806.html";
unsupported_kernel_version["3.8"]["eol_date"] = "2013-05-11";
unsupported_kernel_version["3.8"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/1305.1/02171.html";
unsupported_kernel_version["3.9"]["eol_date"] = "2013-07-21";
unsupported_kernel_version["3.9"]["eol_url"] = "https://lkml.org/lkml/2013/7/21/178";
unsupported_kernel_version["3.10"]["eol_date"] = "2017-11-05";
unsupported_kernel_version["3.10"]["eol_url"] = "https://lkml.org/lkml/2017/11/4/178";
unsupported_kernel_version["3.11"]["eol_date"] = "2013-11-29";
unsupported_kernel_version["3.11"]["eol_url"] = "https://lkml.org/lkml/2013/11/29/327";
unsupported_kernel_version["3.12"]["eol_date"] = "2017-05-10";
unsupported_kernel_version["3.12"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/1705.1/01464.html";
unsupported_kernel_version["3.13"]["eol_date"] = "2014-04-23";
unsupported_kernel_version["3.13"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/1705.1/01464.html";
unsupported_kernel_version["3.14"]["eol_date"] = "2016-09-11";
unsupported_kernel_version["3.14"]["eol_url"] = "https://lkml.org/lkml/2016/9/11/28";
unsupported_kernel_version["3.15"]["eol_date"] = "2014-08-14";
unsupported_kernel_version["3.15"]["eol_url"] = "https://lkml.org/lkml/2014/8/14/7";
# unsupported_kernel_version["3.16"]["eol_date"] = "2020-04-01";
# unsupported_kernel_version["3.16"]["eol_url"] = "https://www.kernel.org/category/releases.html";
unsupported_kernel_version["3.17"]["eol_date"] = "2015-01-08";
unsupported_kernel_version["3.17"]["eol_url"] = "https://lkml.org/lkml/2015/1/8/544";
#unsupported_kernel_version["3.18"]["eol_date"] = "Officially was supposed to be 2017-02-08 but they are still updating it, so...";
#unsupported_kernel_version["3.18"]["eol_url"] = "https://www.kernel.org/category/releases.html";
unsupported_kernel_version["3.19"]["eol_date"] = "2015-05-11";
unsupported_kernel_version["3.19"]["eol_url"] = "https://lkml.org/lkml/2015/5/11/389";
unsupported_kernel_version["4.0"]["eol_date"] = "2015-07-21";
unsupported_kernel_version["4.0"]["eol_url"] = "https://lkml.org/lkml/2015/7/21/965";
unsupported_kernel_version["4.1"]["eol_date"] = "2018-05-29";
unsupported_kernel_version["4.1"]["eol_url"] = "https://www.spinics.net/lists/announce-kernel/msg02259.html";
unsupported_kernel_version["4.2"]["eol_date"] = "2015-12-15";
unsupported_kernel_version["4.2"]["eol_url"] = "https://lkml.org/lkml/2015/12/15/51";
unsupported_kernel_version["4.3"]["eol_date"] = "2016-02-19";
unsupported_kernel_version["4.3"]["eol_url"] = "https://lkml.org/lkml/2016/2/19/699";
# unsupported_kernel_version["4.4"]["eol_date"] = "2022-02-01";
# unsupported_kernel_version["4.4"]["eol_url"] = "https://www.kernel.org/category/releases.html";
unsupported_kernel_version["4.5"]["eol_date"] = "2016-06-07";
unsupported_kernel_version["4.5"]["eol_url"] = "http://www.mail-archive.com/linux-kernel@vger.kernel.org/msg1161793.html";
unsupported_kernel_version["4.6"]["eol_date"] = "2016-08-16";
unsupported_kernel_version["4.6"]["eol_url"] = "https://lkml.org/lkml/2016/8/16/682";
unsupported_kernel_version["4.7"]["eol_date"] = "2016-10-22";
unsupported_kernel_version["4.7"]["eol_url"] = "https://lkml.org/lkml/2016/10/22/112";
unsupported_kernel_version["4.8"]["eol_date"] = "2017-01-09";
unsupported_kernel_version["4.8"]["eol_url"] = "https://lkml.org/lkml/2017/1/9/99";
# unsupported_kernel_version["4.9"]["eol_date"] = "2023-01-01";
# unsupported_kernel_version["4.9"]["eol_url"] = "https://www.kernel.org/category/releases.html";
unsupported_kernel_version["4.10"]["eol_date"] = "2017-05-20";
unsupported_kernel_version["4.10"]["eol_url"] = "https://lkml.org/lkml/2017/5/20/64";
unsupported_kernel_version["4.11"]["eol_date"] = "2017-07-21";
unsupported_kernel_version["4.11"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/1707.2/05562.html";
unsupported_kernel_version["4.12"]["eol_date"] = "2017-09-20";
unsupported_kernel_version["4.12"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/1709.2/02589.html";
unsupported_kernel_version["4.13"]["eol_date"] = "2017-11-24";
unsupported_kernel_version["4.13"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/1711.3/00073.html";
# unsupported_kernel_version["4.14"]["eol_date"] = "2020-01-01";
# unsupported_kernel_version["4.14"]["eol_url"] = "https://www.kernel.org/category/releases.html";
unsupported_kernel_version["4.15"]["eol_date"] = "2018-04-19";
unsupported_kernel_version["4.15"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/1804.2/03399.html";
unsupported_kernel_version["4.16"]["eol_date"] = "2018-06-25";
unsupported_kernel_version["4.16"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/1806.3/01553.html";
unsupported_kernel_version["4.17"]["eol_date"] = "2018-08-24";
unsupported_kernel_version["4.17"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/1808.3/00244.html";
unsupported_kernel_version["4.18"]["eol_date"] = "2018-11-21";
unsupported_kernel_version["4.18"]["eol_url"] = "http://lkml.iu.edu/hypermail/linux/kernel/1811.2/04972.html";
# unsupported_kernel_version["4.19"]["eol_date"] = "2020-12-01";
# unsupported_kernel_version["4.19"]["eol_url"] = "https://www.kernel.org/category/releases.html";
# unsupported_kernel_version["4.20"]["eol_date"] = "";
# unsupported_kernel_version["4.20"]["eol_url"] = "https://www.kernel.org/category/releases.html";
# unsupported_kernel_version["5.0"]["eol_date"] = "";
# unsupported_kernel_version["5.0"]["eol_url"] = "https://www.kernel.org/category/releases.html";

# Check all relevant banner KBs
banners = get_kb_list("*/banner/*");
host_os = get_kb_item("Host/OS");
if (isnull(banners) && isnull(host_os)) exit(0, "Relevant banners and Host/OS keys not present for this scan.");

# Determine if a kernel version is present in the banners and extract it
port = 0;
version = NULL;
foreach banner_kb (sort(keys(banners)))
{
  banner_value = banners[banner_kb];
  regex = "(?:kernel|linux) (\d+\.\d+\.\d+[^\s]*)";
  kernel_version = pregmatch(string:banner_value, pattern:regex, icase:TRUE);
  if(!isnull(kernel_version))
  {
    version = kernel_version[1];
    version -= ".EL";
    # Try and extract port from banner_kb
    portmatch = pregmatch(pattern:"\/(\d+)(?:\/|$)", string:banner_kb);
    if (portmatch)
    {
      port = portmatch[1];
    }
    break;
  }
}

if (isnull(version))
{
  # Try to get the value from Host/OS
  if (!empty_or_null(host_os))
  {
    regex = "Linux Kernel (\d+\.\d+[^\s]*)";
    kernel_version = pregmatch(string:host_os, pattern:regex, icase:TRUE);
    if(!isnull(kernel_version))
    {
      version = kernel_version[1];
    }
  }
}

if (isnull(version))
{
  exit(0, "Unable to find kernel version strings in banner(s) or Host/OS KB entries.");
}

# Trim 2.6 versions down to #.#.#, trim everything else down to #.#
two_six_match = pregmatch(string:version, pattern:"^(2\.6\.\d+)", icase:TRUE);
if(!isnull(two_six_match))
{
  version = two_six_match[1];
}
else
{
  version_match = pregmatch(string:version, pattern:"^(\d+.\d+)", icase:TRUE);
  if(!isnull(version_match))
  {
    version = version_match[1];
  }
}

if (isnull(unsupported_kernel_version[version]))
{
  exit(0, "The remote host's Linux kernel version " + version + " is still supported.");
}
else
{
  eol_date = unsupported_kernel_version[version]["eol_date"];
  eol_url = unsupported_kernel_version[version]["eol_url"];
  supported_levels = unsupported_kernel_version["supported_levels"];
  report =  'Kernel Version:         ' + version + '\n';
  report += 'End of support date:    ' + eol_date + '\n';
  report += 'Details available from: ' + eol_url + '\n';
  report += 'Currently supported kernel versions: ' + supported_levels + '\n';
  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    extra      : report
  );
}
