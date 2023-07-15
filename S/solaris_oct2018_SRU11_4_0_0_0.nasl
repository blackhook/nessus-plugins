#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for oct2018.
#
include("compat.inc");

if (description)
{
  script_id(118189);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/11");

  script_cve_id("CVE-2018-3263", "CVE-2018-3264", "CVE-2018-3265", "CVE-2018-3266", "CVE-2018-3267", "CVE-2018-3268", "CVE-2018-3269", "CVE-2018-3270", "CVE-2018-3271", "CVE-2018-3272", "CVE-2018-3273", "CVE-2018-3274", "CVE-2018-3275");

  script_name(english:"Oracle Solaris Critical Patch Update : oct2018_SRU11_4_0_0_0");
  script_summary(english:"Check for the oct2018 CPU");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Solaris system is missing a security patch from CPU
oct2018."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This Solaris system is missing necessary patches to address critical
security updates :

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Remote
    Administration Daemon (RAD)). The supported version that
    is affected is 11.3. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via
    multiple protocols to compromise Solaris. Successful
    attacks require human interaction from a person other
    than the attacker. Successful attacks of this
    vulnerability can result in unauthorized creation,
    deletion or modification access to critical data or all
    Solaris accessible data as well as unauthorized access
    to critical data or complete access to all Solaris
    accessible data. (CVE-2018-3273)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: LibKMIP). The
    supported version that is affected is 11.3. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise
    Solaris. Successful attacks of this vulnerability can
    result in unauthorized creation, deletion or
    modification access to critical data or all Solaris
    accessible data as well as unauthorized access to
    critical data or complete access to all Solaris
    accessible data. (CVE-2018-3275)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Kernel Zones
    Virtualized NIC Driver). The supported version that is
    affected is 11.3. Easily exploitable vulnerability
    allows unauthenticated attacker with logon to the
    infrastructure where Solaris executes to compromise
    Solaris. Successful attacks of this vulnerability can
    result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of Solaris.
    (CVE-2018-3272)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Kernel). The
    supported version that is affected is 11.3. Easily
    exploitable vulnerability allows low privileged attacker
    with network access via SMB to compromise Solaris.
    Successful attacks require human interaction from a
    person other than the attacker. Successful attacks of
    this vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of Solaris. (CVE-2018-3274)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Sudo). The
    supported version that is affected is 11.3. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise
    Solaris. Successful attacks of this vulnerability can
    result in unauthorized update, insert or delete access
    to some of Solaris accessible data as well as
    unauthorized read access to a subset of Solaris
    accessible data and unauthorized ability to cause a
    partial denial of service (partial DOS) of Solaris.
    (CVE-2018-3263)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: LFTP). The
    supported version that is affected is 11.3. Easily
    exploitable vulnerability allows unauthenticated
    attacker with network access via FTP to compromise
    Solaris. Successful attacks of this vulnerability can
    result in unauthorized read access to a subset of
    Solaris accessible data. (CVE-2018-3267)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Kernel Zones). The
    supported version that is affected is 11.3. Difficult to
    exploit vulnerability allows high privileged attacker
    with logon to the infrastructure where Solaris executes
    to compromise Solaris. While the vulnerability is in
    Solaris, attacks may significantly impact additional
    products. Successful attacks of this vulnerability can
    result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of Solaris.
    (CVE-2018-3271)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: SMB Server). The
    supported version that is affected is 11.3. Easily
    exploitable vulnerability allows unauthenticated
    attacker with network access via SMB to compromise
    Solaris. Successful attacks of this vulnerability can
    result in unauthorized ability to cause a partial denial
    of service (partial DOS) of Solaris. (CVE-2018-3268)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Zones). The
    supported version that is affected is 11.3. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with logon to the infrastructure where Solaris executes
    to compromise Solaris. Successful attacks of this
    vulnerability can result in unauthorized update, insert
    or delete access to some of Solaris accessible data as
    well as unauthorized read access to a subset of Solaris
    accessible data and unauthorized ability to cause a
    partial denial of service (partial DOS) of Solaris.
    (CVE-2018-3265)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Kernel). The
    supported version that is affected is 11.3. Easily
    exploitable vulnerability allows low privileged attacker
    with logon to the infrastructure where Solaris executes
    to compromise Solaris. Successful attacks of this
    vulnerability can result in unauthorized update, insert
    or delete access to some of Solaris accessible data and
    unauthorized ability to cause a partial denial of
    service (partial DOS) of Solaris. (CVE-2018-3264)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: SMB Server). The
    supported version that is affected is 11.3. Easily
    exploitable vulnerability allows low privileged attacker
    with network access via SMB to compromise Solaris.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of
    service (partial DOS) of Solaris. (CVE-2018-3269)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Verified Boot).
    The supported version that is affected is 11.3.
    Difficult to exploit vulnerability allows high
    privileged attacker with logon to the infrastructure
    where Solaris executes to compromise Solaris. Successful
    attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Solaris
    accessible data as well as unauthorized read access to a
    subset of Solaris accessible data and unauthorized
    ability to cause a partial denial of service (partial
    DOS) of Solaris. (CVE-2018-3266)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Kernel). The
    supported version that is affected is 11.3. Difficult to
    exploit vulnerability allows high privileged attacker
    with logon to the infrastructure where Solaris executes
    to compromise Solaris. Successful attacks require human
    interaction from a person other than the attacker.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of
    service (partial DOS) of Solaris. (CVE-2018-3270)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/epmos/faces/DocumentDisplay?id=2451130.1"
  );
  # https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/5115881.xml
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1619b94b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.oracle.com/security-alerts/cpuoct2018.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the oct2018 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3275");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/18");
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


fix_release = "11.4-11.4.0.0.0.0.0";

flag = 0;

if (solaris_check_release(release:"11.4-11.4.0.0.0.0.0", sru:"11.4") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report2());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
