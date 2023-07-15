#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for jan2016.
#
include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(88001);
  script_version("2.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/11");

  script_cve_id("CVE-2015-4920", "CVE-2015-4922", "CVE-2016-0403", "CVE-2016-0414", "CVE-2016-0416", "CVE-2016-0418", "CVE-2016-0419", "CVE-2016-0426", "CVE-2016-0428", "CVE-2016-0431", "CVE-2016-0440");
  script_bugtraq_id(81071, 81076, 81078, 81079, 81084, 81093, 81110, 81112, 81119, 81138, 81149);

  script_name(english:"Oracle Solaris Critical Patch Update : jan2016_SRU11_3_0_0_0");
  script_summary(english:"Check for the jan2016 CPU");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Solaris system is missing a security patch from CPU
jan2016."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This Solaris system is missing necessary patches to address critical
security updates :

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: NDMP Backup
    Service). The supported version that is affected is 11.
    Easily exploitable vulnerability requiring logon to
    Operating System. Successful attack of this
    vulnerability can result in unauthorized update, insert
    or delete access to some Solaris accessible data. Note:
    Unsupported Solaris 11.x versions should be upgraded to
    a supported release or patch set. Refer to the Critical
    Patch Update January 2015 Patch Availability Document
    for Oracle Sun Systems Products Suite. (CVE-2015-4920)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Boot). The
    supported version that is affected is 11. Easily
    exploitable vulnerability requiring logon to Operating
    System. Successful attack of this vulnerability can
    result in unauthorized ability to cause a partial denial
    of service (partial DOS) of Solaris. Note: Unsupported
    Solaris 11.x versions should be upgraded to a supported
    release or patch set. Refer to the Critical Patch Update
    January 2015 Patch Availability Document for Oracle Sun
    Systems Products Suite. (CVE-2015-4922)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: SMB Utilities).
    The supported version that is affected is 11. Easily
    exploitable vulnerability allows successful
    unauthenticated network attacks via SMB. Successful
    attack of this vulnerability can result in unauthorized
    Operating System hang or frequently repeatable crash
    (complete DOS). Note: Unsupported Solaris 11.x versions
    should be upgraded to a supported release or patch set.
    Refer to the Critical Patch Update January 2015 Patch
    Availability Document for Oracle Sun Systems Products
    Suite. (CVE-2016-0403)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Solaris Kernel
    Zones). The supported version that is affected is 11.
    Easily exploitable vulnerability requiring logon to
    Operating System. Successful attack of this
    vulnerability can result in unauthorized Operating
    System takeover including arbitrary code execution.
    Note: Unsupported Solaris 11.x versions should be
    upgraded to a supported release or patch set. Refer to
    the Critical Patch Update January 2015 Patch
    Availability Document for Oracle Sun Systems Products
    Suite. (CVE-2016-0414)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: System Archive
    Utility). The supported version that is affected is 11.
    Easily exploitable vulnerability allows successful
    unauthenticated network attacks via multiple protocols.
    Successful attack of this vulnerability can result in
    unauthorized update, insert or delete access to some
    Solaris accessible data. Note: Unsupported Solaris 11.x
    versions should be upgraded to a supported release or
    patch set. Refer to the Critical Patch Update January
    2015 Patch Availability Document for Oracle Sun Systems
    Products Suite. (CVE-2016-0416)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Solaris Kernel
    Zones). The supported version that is affected is 11.
    Easily exploitable vulnerability requiring logon to
    Operating System. Successful attack of this
    vulnerability can result in unauthorized Operating
    System hang or frequently repeatable crash (complete
    DOS) as well as update, insert or delete access to some
    Solaris accessible data and read access to a subset of
    Solaris accessible data. Note: Unsupported Solaris 11.x
    versions should be upgraded to a supported release or
    patch set. Refer to the Critical Patch Update January
    2015 Patch Availability Document for Oracle Sun Systems
    Products Suite. (CVE-2016-0418)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Solaris Kernel
    Zones). The supported version that is affected is 11.
    Easily exploitable vulnerability requiring logon to
    Operating System. Successful attack of this
    vulnerability can result in unauthorized Operating
    System hang or frequently repeatable crash (complete
    DOS). Note: Unsupported Solaris 11.x versions should be
    upgraded to a supported release or patch set. Refer to
    the Critical Patch Update January 2015 Patch
    Availability Document for Oracle Sun Systems Products
    Suite. (CVE-2016-0419)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Solaris Kernel
    Zones). The supported version that is affected is 11.
    Easily exploitable vulnerability requiring logon to
    Operating System. Successful attack of this
    vulnerability can result in unauthorized read access to
    a subset of Solaris accessible data and ability to cause
    a partial denial of service (partial DOS) of Solaris.
    Note: Unsupported Solaris 11.x versions should be
    upgraded to a supported release or patch set. Refer to
    the Critical Patch Update January 2015 Patch
    Availability Document for Oracle Sun Systems Products
    Suite. (CVE-2016-0426)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Verified Boot).
    The supported version that is affected is 11. Easily
    exploitable vulnerability requiring logon to Operating
    System. Successful attack of this vulnerability can
    result in unauthorized Operating System hang or
    frequently repeatable crash (complete DOS). Note:
    Unsupported Solaris 11.x versions should be upgraded to
    a supported release or patch set. Refer to the Critical
    Patch Update January 2015 Patch Availability Document
    for Oracle Sun Systems Products Suite. (CVE-2016-0428)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Solaris Kernel
    Zones). The supported version that is affected is 11.
    Very difficult to exploit vulnerability requiring logon
    to Operating System. Successful attack of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of
    Solaris. Note: Unsupported Solaris 11.x versions should
    be upgraded to a supported release or patch set. Refer
    to the Critical Patch Update January 2015 Patch
    Availability Document for Oracle Sun Systems Products
    Suite. (CVE-2016-0431)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: NFSv4). The
    supported version that is affected is 11. Easily
    exploitable vulnerability allows successful
    unauthenticated network attacks via NFS. Successful
    attack of this vulnerability can result in unauthorized
    Operating System hang or frequently repeatable crash
    (complete DOS). (CVE-2016-0440)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/epmos/faces/DocumentDisplay?id=2091648.1"
  );
  # https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/2368796.xml
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?10ceb1c6"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the jan2016 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/20");
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


fix_release = "0.5.11-0.175.3.0.0.0.0";

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.3.0.0.0.0", sru:"11.3") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report2());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
