#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(52631);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2010-1321", "CVE-2010-3574", "CVE-2010-4476");

  script_name(english:"SuSE 11.1 Security Update : IBM Java (SAT Patch Number 4024)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IBM Java 1.4.2 SR13 was updated to FP8 to fix various bugs and
security issues.

The following security issues were fixed :

  - The kg_accept_krb5 function in krb5/accept_sec_context.c
    in the GSS-API library in MIT Kerberos 5 (aka krb5)
    through 1.7.1 and 1.8 before 1.8.2, as used in kadmind
    and other applications, does not properly check for
    invalid GSS-API tokens, which allows remote
    authenticated users to cause a denial of service (NULL
    pointer dereference and daemon crash) via an AP-REQ
    message in which the authenticator's checksum field is
    missing. (CVE-2010-1321)

  - Unspecified vulnerability in the Networking component in
    Oracle Java SE and Java for Business 6 Update 21, 5.0
    Update 25, 1.4.2_27, and 1.3.1_28 allows remote
    attackers to affect confidentiality, integrity, and
    availability via unknown vectors. NOTE: the previous
    information was obtained from the October 2010 CPU.
    Oracle has not commented on claims from a reliable
    downstream vendor that HttpURLConnection does not
    properly check for the allowHttpTrace permission, which
    allows untrusted code to perform HTTP TRACE requests.
    (CVE-2010-3574)

  - The Java Runtime Environment hangs forever when
    converting '2.2250738585072012e-308' to a binary
    floating-point number. (CVE-2010-4476)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=663953"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=673738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1321.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3574.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4476.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 4024.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_4_2-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_4_2-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_4_2-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLES11", sp:1, reference:"java-1_4_2-ibm-1.4.2_sr13.8-1.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"java-1_4_2-ibm-jdbc-1.4.2_sr13.8-1.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"java-1_4_2-ibm-plugin-1.4.2_sr13.8-1.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
