#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100997);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2017-3629",
    "CVE-2017-3630",
    "CVE-2017-3631"
  );
  script_bugtraq_id(
    99150,
    99151,
    99153
  );

  script_name(english:"Solaris 11 : Multiple Kernel Vulnerabilities");
  script_summary(english:"Checks the release version of the Solaris kernel.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Solaris host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description",  value:
"The remote Solaris host is missing a vendor-supplied security patch.
It is, therefore, affected by the following vulnerabilities :

  - Multiple security bypass vulnerabilities exist in the
    Kernel subcomponent that allow a specially crafted
    application to circumvent the stack guard page security
    mechanism. A local attacker can exploit these, by using
    stack clash methods, to gain elevated privileges.
    (CVE-2017-3629, CVE-2017-3630)

  - A privilege escalation vulnerability exists in the
    Kernel subcomponent when UID binaries are invoked via a
    hard-link using a different pathname. A local attacker
    can exploit this to gain elevated privileges.
    (CVE-2017-3631)");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3757499.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc84c529");
  # http://www.oracle.com/technetwork/security-advisory/alert-cve-2017-3629-3757403.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1490b6d");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2277900.1");
  script_set_attribute(attribute:"solution", value:
"Install SRU 11.3.21.5.0 from the Oracle support website.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Solaris RSH Stack Clash Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Solaris Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");


fix_release = "0.5.11-0.175.3.21.0.5.0";

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.3.21.0.5.0", sru:"11.3.21.5.0") > 0) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : solaris_get_report2()
  );
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", "a version below " + fix_release, release);
