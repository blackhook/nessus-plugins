#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for oct2016.
#
include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(94134);
  script_version("2.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/11");

  script_cve_id("CVE-2016-5487", "CVE-2016-5553", "CVE-2016-5566", "CVE-2016-5576", "CVE-2016-5615");

  script_name(english:"Oracle Solaris Critical Patch Update : oct2016_SRU11_3_12_4_0");
  script_summary(english:"Check for the oct2016 CPU");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Solaris system is missing a security patch from CPU
oct2016."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This Solaris system is missing necessary patches to address critical
security updates :

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Files). The
    supported version that is affected is 11.3. Easily
    exploitable vulnerability allows low privileged attacker
    with logon to the infrastructure where Solaris executes
    to compromise Solaris. Successful attacks of this
    vulnerability can result in unauthorized update, insert
    or delete access to some of Solaris accessible data as
    well as unauthorized read access to a subset of Solaris
    accessible data and unauthorized ability to cause a
    partial denial of service (partial DOS) of Solaris.
    (CVE-2016-5487)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Filesystem).
    Supported versions that are affected are 10 and 11.3.
    Easily exploitable vulnerability allows low privileged
    attacker with logon to the infrastructure where Solaris
    executes to compromise Solaris. Successful attacks
    require human interaction from a person other than the
    attacker. Successful attacks of this vulnerability can
    result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of Solaris.
    (CVE-2016-5553)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Installation). The
    supported version that is affected is 11.3. Easily
    exploitable vulnerability allows unauthenticated
    attacker with network access via HTTP to compromise
    Solaris. Successful attacks of this vulnerability can
    result in unauthorized read access to a subset of
    Solaris accessible data. (CVE-2016-5566)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Kernel Zones). The
    supported version that is affected is 11.3. Easily
    exploitable vulnerability allows low privileged attacker
    with logon to the infrastructure where Solaris executes
    to compromise Solaris. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of Solaris. (CVE-2016-5576)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Lynx). The
    supported version that is affected is 11.3. Easily
    exploitable vulnerability allows low privileged attacker
    with logon to the infrastructure where Solaris executes
    to compromise Solaris. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of
    Solaris. (CVE-2016-5615)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/epmos/faces/DocumentDisplay?id=2189657.1"
  );
  # https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3235388.xml
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?453a538d"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the oct2016 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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


fix_release = "0.5.11-0.175.3.12.0.4.0";

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.3.12.0.4.0", sru:"11.3.12.4.0") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report2());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
