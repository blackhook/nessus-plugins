#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for jan2017.
#
include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(96602);
  script_version("3.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/11");

  script_cve_id("CVE-2017-3301");
  script_bugtraq_id(95567);

  script_name(english:"Oracle Solaris Critical Patch Update : jan2017_SRU11_3_16_3_0");
  script_summary(english:"Check for the jan2017 CPU");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Solaris system is missing a security patch from CPU
jan2017."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This Solaris system is missing necessary patches to address a critical
security update :

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Kernel). The
    supported version that is affected is 11.3. Easily
    exploitable vulnerability allows unauthenticated
    attacker with logon to the infrastructure where Solaris
    executes to compromise Solaris. Successful attacks
    require human interaction from a person other than the
    attacker. Successful attacks of this vulnerability can
    result in unauthorized update, insert or delete access
    to some of Solaris accessible data. (CVE-2017-3301)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/epmos/faces/DocumentDisplay?id=2220066.1"
  );
  # https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3432537.xml
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?724b555f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.oracle.com/security-alerts/cpujan2017.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the jan2017 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Solaris Local Security Checks");

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


fix_release = "0.5.11-0.175.3.16.0.3.0";

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.3.16.0.3.0", sru:"11.3.16.3.0") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:solaris_get_report2());
  else security_note(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
