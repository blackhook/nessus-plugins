#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124910);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2017-0898",
    "CVE-2017-0899",
    "CVE-2017-0900",
    "CVE-2017-0901",
    "CVE-2017-0902",
    "CVE-2017-0903",
    "CVE-2017-10784",
    "CVE-2017-14033",
    "CVE-2017-14064",
    "CVE-2017-17405",
    "CVE-2017-17790"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : ruby (EulerOS-SA-2019-1407)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ruby packages installed, the EulerOS
Virtualization for ARM 64 installation on the remote host is affected
by the following vulnerabilities :

  - It was discovered that the Net::FTP module did not
    properly process filenames in combination with certain
    operations. A remote attacker could exploit this flaw
    to execute arbitrary commands by setting up a malicious
    FTP server and tricking a user or Ruby application into
    downloading files with specially crafted names using
    the Net::FTP module.(CVE-2017-17405)

  - The 'lazy_initialize' function in lib/resolv.rb did not
    properly process certain filenames. A remote attacker
    could possibly exploit this flaw to inject and execute
    arbitrary commands.(CVE-2017-17790)

  - It was found that rubygems could use an excessive
    amount of CPU while parsing a sufficiently long gem
    summary. A specially crafted gem from a gem repository
    could freeze gem commands attempting to parse its
    summary.(CVE-2017-0900)

  - It was found that rubygems did not sanitize gem names
    during installation of a given gem. A specially crafted
    gem could use this flaw to install files outside of the
    regular directory.(CVE-2017-0901)

  - A vulnerability was found where rubygems did not
    sanitize DNS responses when requesting the hostname of
    the rubygems server for a domain, via a _rubygems._tcp
    DNS SRV query. An attacker with the ability to
    manipulate DNS responses could direct the gem command
    towards a different domain.(CVE-2017-0902)

  - A vulnerability was found where rubygems did not
    properly sanitize gems' specification text. A specially
    crafted gem could interact with the terminal via the
    use of escape sequences.(CVE-2017-0899)

  - A buffer overflow vulnerability was found in the JSON
    extension of ruby. An attacker with the ability to pass
    a specially crafted JSON input to the extension could
    use this flaw to expose the inter preter's heap
    memory.(CVE-2017-14064)

  - It was found that WEBrick did not sanitize all its log
    messages. If logs were printed in a terminal, an
    attacker could interact with the terminal via the use
    of escape sequences.(CVE-2017-10784)

  - It was found that the decode method of the
    OpenSSL::ASN1 module was vulnerable to buffer underrun.
    An attacker could pass a specially crafted string to
    the application in order to crash the ruby interpreter,
    causing a denial of service.(CVE-2017-14033)

  - A buffer underflow was found in ruby's sprintf
    function. An attacker, with ability to control its
    format string parameter, could send a specially crafted
    string that would disclose heap memory or crash the
    interpreter.(CVE-2017-0898)

  - A vulnerability was found where the rubygems module was
    vulnerable to an unsafe YAML deserialization when
    inspecting a gem. Applications inspecting gem files
    without installing them can be tricked to execute
    arbitrary code in the context of the ruby
    interpreter.(CVE-2017-0903)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1407
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f513ca9e");
  script_set_attribute(attribute:"solution", value:
"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-17405");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-17790");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rubygems");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["ruby-2.0.0.648-33.h11",
        "ruby-irb-2.0.0.648-33.h11",
        "ruby-libs-2.0.0.648-33.h11",
        "rubygem-bigdecimal-1.2.0-33.h11",
        "rubygem-io-console-0.4.2-33.h11",
        "rubygem-json-1.7.7-33.h11",
        "rubygem-psych-2.0.0-33.h11",
        "rubygem-rdoc-4.0.0-33.h11",
        "rubygems-2.0.14.1-33.h11"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby");
}
