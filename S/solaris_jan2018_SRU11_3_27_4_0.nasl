#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for jan2018.
#
include("compat.inc");

if (description)
{
  script_id(106126);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/11");

  script_cve_id("CVE-2018-2560", "CVE-2018-2577", "CVE-2018-2578");

  script_name(english:"Oracle Solaris Critical Patch Update : jan2018_SRU11_3_27_4_0");
  script_summary(english:"Check for the jan2018 CPU");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Solaris system is missing a security patch from CPU
jan2018."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This Solaris system is missing necessary patches to address critical
security updates :

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Kernel). The
    supported version that is affected is 11.3. Difficult to
    exploit vulnerability allows high privileged attacker
    with logon to the infrastructure where Solaris executes
    to compromise Solaris. Successful attacks require human
    interaction from a person other than the attacker and
    while the vulnerability is in Solaris, attacks may
    significantly impact additional products. Successful
    attacks of this vulnerability can result in unauthorized
    access to critical data or complete access to all
    Solaris accessible data. (CVE-2018-2560)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Kernel). The
    supported version that is affected is 11.3. Easily
    exploitable vulnerability allows low privileged attacker
    with logon to the infrastructure where Solaris executes
    to compromise Solaris. Successful attacks of this
    vulnerability can result in unauthorized access to
    critical data or complete access to all Solaris
    accessible data. (CVE-2018-2577)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Kernel). The
    supported version that is affected is 11.3. Difficult to
    exploit vulnerability allows high privileged attacker
    with logon to the infrastructure where Solaris executes
    to compromise Solaris. Successful attacks require human
    interaction from a person other than the attacker and
    while the vulnerability is in Solaris, attacks may
    significantly impact additional products. Successful
    attacks of this vulnerability can result in takeover of
    Solaris. (CVE-2018-2578)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/epmos/faces/DocumentDisplay?id=2336753.1"
  );
  # https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/4110638.xml
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17a0bb67"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.oracle.com/security-alerts/cpujan2018.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the jan2018 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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


fix_release = "0.5.11-0.175.3.27.0.4.0";

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.3.27.0.4.0", sru:"11.3.27.4.0") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report2());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
