#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119065);
  script_version("1.38");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id(
    "CVE-2014-4975",
    "CVE-2014-8080",
    "CVE-2014-8090"
  );
  script_bugtraq_id(
    68474,
    70935,
    71230
  );

  script_name(english:"EulerOS Virtualization 2.5.1 : ruby (EulerOS-SA-2018-1374)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ruby packages installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - The REXML parser in Ruby 1.9.x before 1.9.3-p550, 2.0.x
    before 2.0.0-p594, and 2.1.x before 2.1.4 allows remote
    attackers to cause a denial of service (memory
    consumption) via a crafted XML document, aka an XML
    Entity Expansion (XEE) attack.i1/4^CVE-2014-8080i1/4%0

  - The REXML parser in Ruby 1.9.x before 1.9.3 patchlevel
    551, 2.0.x before 2.0.0 patchlevel 598, and 2.1.x
    before 2.1.5 allows remote attackers to cause a denial
    of service (CPU and memory consumption) a crafted XML
    document containing an empty string in an entity that
    is used in a large number of nested entity references,
    aka an XML Entity Expansion (XEE) attack. NOTE: this
    vulnerability exists because of an incomplete fix for
    CVE-2013-1821 and CVE-2014-8080.i1/4^CVE-2014-8090i1/4%0

  - Off-by-one error in the encodes function in pack.c in
    Ruby 1.9.3 and earlier, and 2.x through 2.1.2, when
    using certain format string specifiers, allows
    context-dependent attackers to cause a denial of
    service (segmentation fault) via vectors that trigger a
    stack-based buffer overflow.(CVE-2014-4975)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1374
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?688a1521");
  script_set_attribute(attribute:"solution", value:
"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/21");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.5.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "2.5.1") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.5.1");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["ruby-2.0.0.353-23.h9",
        "ruby-irb-2.0.0.353-23.h9",
        "ruby-libs-2.0.0.353-23.h9",
        "rubygem-bigdecimal-1.2.0-23.h9",
        "rubygem-io-console-0.4.2-23.h9",
        "rubygem-json-1.7.7-23.h9",
        "rubygem-psych-2.0.0-23.h9",
        "rubygem-rdoc-4.0.0-23.h9",
        "rubygems-2.0.14-23.h9"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
