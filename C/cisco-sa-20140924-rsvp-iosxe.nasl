#TRUSTED 07e518e9d5552b9337f4d651d1888fd32f8adcabd75b56a8144e4fde017c24a5974214ed6d92ed0e7b6bd420ff8ff15e4f97313bdd9e1dcaafcdcac377f9eb05d759c93a44c229a9f88b5460e845005fecd17129b5fb4d8f0da450b99cf01aeecd3283b8e426888b658892f6ee9a1bfd2fecec1073337598c4a1278d58546ebc50dc68c573ff7c8733778d7bde93c87f4b60252508d70cb87317d076bc4dcdfb472fce012428ca12962ea24c6fec785939c8b0184f01e32c8bccda9385d459c530d27f3d33207042efea3c47d66f27798e8dd3eabfe50a2779385f58d3d68e35eecf65dbdfef6c60f2b6aebd303d350c3a73ccac85bff45f39c54489b922572a7683fe0f74ab3a67317f5d80409919b486308bdf813ad8df0c8e096c1bcc490c66cbc31b8dbe595ef150ffb36c03b535cbedb4cabc4fb1fafc54a39ffa08d4174386343f648059f95f91c35fda84f24217bb545629c59cb1d50a3f6b1f9ab8565a099a1c941c94a42626f72a3282443a86ef411a5547baec750099f2fc76890a7f7921f4dcbe9f8222de4eccd0c882af1a1f18d45c1ab441745c4a77edbd4f25a18585beaf4f8e97462360b96e2f3ed30eb6917519d122499eaa6c961838a4c9c101c68aff08cee8bc35c69523d939c0142610c01f64bba270bf85c3988d9898ede25ba8a1b808444f456818c0bf438dd93fd32a67628ab7430ab32e72fafce3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78034);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-3354");
  script_bugtraq_id(70131);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui11547");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140924-rsvp");

  script_name(english:"Cisco IOS XE Software RSVP DoS (cisco-sa-20140924-rsvp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by a denial of service
vulnerability in the Resource Reservation Protocol (RSVP)
implementation due to improper handling of RSVP packets. A remote
attacker can exploit this issue by sending specially crafted RSVP
packets to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140924-rsvp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39016c7b");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35621");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCui11547");

  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140924-rsvp.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/02");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

app = "Cisco IOS XE";
cbi = "CSCui11547";
fixed_ver = NULL;

if (
  ver =~ "^2\.[16]\.[0-2]$" ||
  ver =~ "^2\.2\.[1-3]$" ||
  ver =~ "^2\.3\.([02]|[01]t)$" ||
  ver =~ "^2\.4\.[01]$" ||
  ver == "2.5.0" ||
  ver =~ "^3\.1\.[0-3]S$" ||
  ver =~ "^3\.[2356]\.[0-2]S$" ||
  ver =~ "^3\.4\.[0-6]S$" ||
  ver =~ "^3\.7\.[0-3]S$"
)
  fixed_ver = "3.7.6S";

else if (
  ver =~ "^3\.2\.[01]SE$" ||
  ver =~ "^3\.3\.[01]SE$"
)
  fixed_ver = "3.3.2SE";

else if (
  ver =~ "^3\.3\.[0-2]SG$" ||
  ver =~ "^3\.4\.[0-2]SG$"
)
  fixed_ver = "3.4.4SG";

else if (
  ver =~ "^3\.8\.[0-2]S$" ||
  ver =~ "^3\.9\.[01]S$" ||
  ver == "3.10.0S"
)
  fixed_ver = "3.10.4S";

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);


# RSVP check
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^\s*(?:ip rsvp bandwidth|mpls traffic-eng tunnel)", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because RSVP is not enabled.");
}

if (report_verbosity > 0)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + 
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
