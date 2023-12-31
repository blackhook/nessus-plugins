#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99757);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-3622");
  script_bugtraq_id(97774);
  script_xref(name:"EDB-ID", value:"41871");

  script_name(english:"Solaris 10 (x86) : 152650-02 : dtappgather Arbitrary Directory Creation Local Privilege Escalation (EXTREMEPARR)");
  script_summary(english:"Check for patch 152650-02.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing Sun Security Patch number 152650-02.");
  script_set_attribute(attribute:"description", value:
"The remote Solaris host is missing patch number 152650-02. It is,
therefore, affected by a local privilege escalation vulnerability in
the dtappgather binary due to improper handling of user-supplied
arguments. A local attacker can exploit this, via a specially crafted
command, to manipulate file permissions and create a user-owned
directory anywhere on the system with root privileges. The attacker
can then add shared objects to the folder and run setuid binaries with
a library file, resulting in root privileges.

EXTREMEPARR is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2017/04/08 by a group known as the Shadow
Brokers.");
  script_set_attribute(attribute:"see_also", value:"https://getupdates.oracle.com/readme/152650-02");
  # https://threatpost.com/record-oracle-patch-update-addresses-shadowbrokers-struts-2-vulnerabilities/125046/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b55ae27");
  # https://packetstormsecurity.com/files/142120/Solaris-x86-SPARC-EXTREMEPARR-dtappgather-Privilege-Escalation.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32212782");
  script_set_attribute(attribute:"solution", value:
"You should install patch 152650-02 for your system to be up-to-date.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Solaris "EXTREMEPARR" dtappgather Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/01");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"152650-02", obsoleted_by:"", package:"SUNWdtdte", version:"1.6,REV=10.2004.12.17") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
