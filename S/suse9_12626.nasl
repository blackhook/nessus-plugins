#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(49101);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2010-0084",
    "CVE-2010-0085",
    "CVE-2010-0087",
    "CVE-2010-0088",
    "CVE-2010-0089",
    "CVE-2010-0091",
    "CVE-2010-0095",
    "CVE-2010-0839",
    "CVE-2010-0840",
    "CVE-2010-0841",
    "CVE-2010-0842",
    "CVE-2010-0843",
    "CVE-2010-0844",
    "CVE-2010-0846",
    "CVE-2010-0847",
    "CVE-2010-0848",
    "CVE-2010-0849"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"SuSE9 Security Update : IBM Java (YOU Patch Number 12626)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SuSE 9 host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"This update brings IBM Java 1.4.2 to SR13 FP5, fixing various bugs and
security issues :

  - Unspecified vulnerability in the Java Runtime
    Environment component in Oracle Java SE and Java for
    Business 6 Update 18, 5.0 Update 23, and 1.4.2_25 allows
    remote attackers to affect confidentiality via unknown
    vectors. (CVE-2010-0084)

  - Unspecified vulnerability in the Java Runtime
    Environment component in Oracle Java SE and Java for
    Business 6 Update 18, 5.0 Update 23, 1.4.225, and
    1.3.127 allows remote attackers to affect
    confidentiality, integrity, and availability via unknown
    vectors. (CVE-2010-0085)

  - Unspecified vulnerability in the Java Web Start, Java
    Plug-in component in Oracle Java SE and Java for
    Business 6 Update 18, 5.0 Update 23, 1.4.225, and
    1.3.127 allows remote attackers to affect
    confidentiality, integrity, and availability via unknown
    vectors. (CVE-2010-0087)

  - Unspecified vulnerability in the Java Runtime
    Environment component in Oracle Java SE and Java for
    Business 6 Update 18, 5.0 Update 23, 1.4.225, and
    1.3.127 allows remote attackers to affect
    confidentiality, integrity, and availability via unknown
    vectors. (CVE-2010-0088)

  - Unspecified vulnerability in the Java Web Start, Java
    Plug-in component in Oracle Java SE and Java for
    Business 6 Update 18, 5.0 Update 23, and 1.4.2_25 allows
    remote attackers to affect availability via unknown
    vectors. (CVE-2010-0089)

  - Unspecified vulnerability in the Java Runtime
    Environment component in Oracle Java SE and Java for
    Business 6 Update 18, 5.0 Update 23, and 1.4.2_25 allows
    remote attackers to affect confidentiality via unknown
    vectors. (CVE-2010-0091)

  - Unspecified vulnerability in the Java Runtime
    Environment component in Oracle Java SE and Java for
    Business 6 Update 18, 5.0 Update 23, and 1.4.2_25 allows
    remote attackers to affect confidentiality, integrity,
    and availability via unknown vectors. (CVE-2010-0095)

  - Unspecified vulnerability in the Sound component in
    Oracle Java SE and Java for Business 6 Update 18, 5.0
    Update 23, 1.4.2_25, and 1.3.1_27 allows remote
    attackers to affect confidentiality, integrity, and
    availability via unknown vectors. (CVE-2010-0839)

  - Unspecified vulnerability in the Java Runtime
    Environment component in Oracle Java SE and Java for
    Business 6 Update 18, 5.0 Update 23, and 1.4.2_25 allows
    remote attackers to affect confidentiality, integrity,
    and availability via unknown vectors. NOTE: the previous
    information was obtained from the March 2010 CPU. Oracle
    has not commented on claims from a reliable researcher
    that this is related to improper checks when executing
    privileged methods in the Java Runtime Environment
    (JRE), which allows attackers to execute arbitrary code
    via (1) an untrusted object that extends the trusted
    class but has not modified a certain method, or (2) 'a
    similar trust issue with interfaces,' aka 'Trusted
    Methods Chaining Remote Code Execution Vulnerability.'.
    (CVE-2010-0840)

  - Unspecified vulnerability in the ImageIO component in
    Oracle Java SE and Java for Business 6 Update 18, 5.0
    Update 23, and 1.4.2_25 allows remote attackers to
    affect confidentiality, integrity, and availability via
    unknown vectors. NOTE: the previous information was
    obtained from the March 2010 CPU. Oracle has not
    commented on claims from a reliable researcher that this
    is an integer overflow in the Java Runtime Environment
    that allows remote attackers to execute arbitrary code
    via a JPEG image that contains subsample dimensions with
    large values, related to JPEGImageReader and 'stepX'.
    (CVE-2010-0841)

  - Unspecified vulnerability in the Sound component in
    Oracle Java SE and Java for Business 6 Update 18, 5.0
    Update 23, 1.4.2_25, and 1.3.1_27 allows remote
    attackers to affect confidentiality, integrity, and
    availability via unknown vectors. NOTE: the previous
    information was obtained from the March 2010 CPU. Oracle
    has not commented on claims from a reliable researcher
    that this is an uncontrolled array index that allows
    remote attackers to execute arbitrary code via a MIDI
    file with a crafted MixerSequencer object, related to
    the GM_Song structure. (CVE-2010-0842)

  - Unspecified vulnerability in the Sound component in
    Oracle Java SE and Java for Business 6 Update 18, 5.0
    Update 23, 1.4.2_25, and 1.3.1_27 allows remote
    attackers to affect confidentiality, integrity, and
    availability via unknown vectors. NOTE: the previous
    information was obtained from the March 2010 CPU. Oracle
    has not commented on claims from a reliable researcher
    that this is related to XNewPtr and improper handling of
    an integer parameter when allocating heap memory in the
    com.sun.media.sound libraries, which allows remote
    attackers to execute arbitrary code. (CVE-2010-0843)

  - Unspecified vulnerability in the Sound component in
    Oracle Java SE and Java for Business 6 Update 18, 5.0
    Update 23, 1.4.2_25, and 1.3.1_27 allows remote
    attackers to affect confidentiality, integrity, and
    availability via unknown vectors. NOTE: the previous
    information was obtained from the March 2010 CPU. Oracle
    has not commented on claims from a reliable researcher
    that this is for improper parsing of a crafted MIDI
    stream when creating a MixerSequencer object, which
    causes a pointer to be corrupted and allows a NULL byte
    to be written to arbitrary memory. (CVE-2010-0844)

  - Unspecified vulnerability in the ImageIO component in
    Oracle Java SE and Java for Business 6 Update 18, 5.0
    Update 23, 1.4.2_25, and 1.3.1_27 allows remote
    attackers to affect confidentiality, integrity, and
    availability via unknown vectors. NOTE: the previous
    information was obtained from the March 2010 CPU. Oracle
    has not commented on claims from a reliable researcher
    that this is a heap-based buffer overflow that allows
    remote attackers to execute arbitrary code, related to
    an 'invalid assignment' and inconsistent length values
    in a JPEG image encoder (JPEGImageEncoderImpl).
    (CVE-2010-0846)

  - Unspecified vulnerability in the Java 2D component in
    Oracle Java SE and Java for Business 6 Update 18, 5.0
    Update 23, 1.4.2_25, and 1.3.1_27 allows remote
    attackers to affect confidentiality, integrity, and
    availability via unknown vectors. NOTE: the previous
    information was obtained from the March 2010 CPU. Oracle
    has not commented on claims from a reliable researcher
    that this is a heap-based buffer overflow that allows
    arbitrary code execution via a crafted image.
    (CVE-2010-0847)

  - Unspecified vulnerability in the Java 2D component in
    Oracle Java SE and Java for Business 6 Update 18, 5.0
    Update 23, 1.4.2_25, and 1.3.1_27 allows remote
    attackers to affect confidentiality, integrity, and
    availability via unknown vectors. (CVE-2010-0848)

  - Unspecified vulnerability in the Java 2D component in
    Oracle Java SE and Java for Business 6 Update 18, 5.0
    Update 23, 1.4.2_25, and 1.3.1_27 allows remote
    attackers to affect confidentiality, integrity, and
    availability via unknown vectors. NOTE: the previous
    information was obtained from the March 2010 CPU. Oracle
    has not commented on claims from a reliable researcher
    that this is a heap-based buffer overflow in a decoding
    routine used by the JPEGImageDecoderImpl interface,
    which allows code execution via a crafted JPEG image.
    (CVE-2010-0849)");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0084.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0085.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0087.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0088.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0089.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0091.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0095.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0839.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0840.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0841.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0842.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0843.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0844.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0846.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0847.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0848.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0849.html");
  script_set_attribute(attribute:"solution", value:
"Apply YOU patch number 12626.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java MixerSequencer Object GM_Song Structure Handling Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 9 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SUSE9", reference:"IBMJava2-JRE-1.4.2_sr13.5-0.7")) flag++;
if (rpm_check(release:"SUSE9", reference:"IBMJava2-SDK-1.4.2_sr13.5-0.7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
