#TRUSTED 55f8abc13bc01e2f86e92e52334ce8e23e2513e6af2b14d2d63bb99b01e2479e5ea93cb9035f17bfb4a5fb20755dfe7bbf1ebc750a1aec6be733d15b6927c80ee66f9484fd1d299b26ab06234974907d5aa056068b7f30d0ac0c9679cc3555791d528cd2aeddd68068917d7a4221d8f11fe17ca79e92b68d1ed3baeefb04261193df7f4205fbfe8317c50ad51b8b56da858500e676b28e4377d5626d880d361b94fd1805fda0e77a1d2bb8971fb463ea2a5046053cd5703b95f882840e24d9420e0645bdbb2935a6ae1bcead380cbc48a832655f02e1c7f229a039414bdf9d074b3f952fc642ccb0f571a2bf2de7dc2ab2a12c41a2868112381b2cb18e922d6796450d487a0c6f56256fb4752a537aa62d2f8f332db531c6a1c58808ba705f6b29326898deb26cccf8a7f8a0c55afc613479e017d472bd73d974654ec82c7aa01d75ec768c767311fac730930043208a10937f083ae705647fd168b6b38e64d476ef86c553f38c4a1ff87a99ace5c5fff29ed249a1ba2483d98b4b8f67c6ba79b3d7eb903660394bc8f76f294f7dd50e0b52c5865ef698a699591503b7072b50aa375040355368afc0b8f59b6c9cbe592097b0dcacf6c063ccc000490ac76f08e8b40eebfdbebfead04c388134ccaa37a3f55e9193f96ea3a5f3482fac04b2c86cfc91db110eb36a0bb6133a701f476ce8e581e31270d3ef19c3d184df5541d8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82585);
  script_version("1.13");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-0635", "CVE-2015-0636", "CVE-2015-0637");
  script_bugtraq_id(73339, 73341, 73343);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup62191");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup62293");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup62315");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150325-ani");

  script_name(english:"Cisco IOS XE Autonomic Networking Infrastructure Multiple Vulnerabilities (cisco-sa-20150325-ani)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS
running on the remote host is affected by the following
vulnerabilities :

  - A flaw exists in the ANI due to failing to properly
    validate Autonomic Networking (AN) messages. This could
    allow a remote attacker to spoof an Autonomic Networking
    Registration Authority (ANRA) response and gain elevated
    privileges or cause a denial of service. (CVE-2015-0635)

  - A flaw exists in the ANI due to imporperly handling AN
    messages. This could allow a remote attacker, with a
    specially crafted AN message, to disrupt autonomic
    domain services. (CVE-2015-0636)

  - A flaw exists in the ANI due to improperly validating AN
    messages. This could allow a remote attacker, with a
    specially crafted An message, to cause the device to
    reload. (CVE-2015-0637)

Note that these issues only affect devices with ANI enabled.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-ani
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dabca9f4");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37811");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37812");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37813");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

model = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");

if (
  model !~ '^ASR90(1S?|3)$' &&
  model !~ '^ME-3(600X?|800)-'
) audit(AUDIT_HOST_NOT, 'affected');

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

fix = '';
flag = 0;

# Check for vuln version
if (
  ver =~ "^3\.10(\.[0-5])?S([^EG]|$)" ||
  ver =~ "^3\.11(\.[0-3])?S([^EG]|$)" ||
  ver =~ "^3\.12(\.[0-3])?S([^EG]|$)" ||
  ver =~ "^3\.13\.0?S([^EG]|$)"
)
{
  fix = "3.13.1S";
  flag++;
}

# Check that ANI is running
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_run_autonomic","show run | include autonomic");
  if (check_cisco_result(buf))
  {
    if (
      ( !empty_or_null(buf) ) &&
      ( "no autonomic" >!< buf )
    ) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (fix && flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCup62191, CSCup62293, and CSCup62315' +
      '\n  Installed release : ' + ver +
      '\n  Fixed release     : ' + fix +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
