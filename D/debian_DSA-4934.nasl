#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4934. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(151037);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/17");

  script_cve_id("CVE-2020-24489", "CVE-2020-24511", "CVE-2020-24512", "CVE-2020-24513");
  script_xref(name:"DSA", value:"4934");

  script_name(english:"Debian DSA-4934-1 : intel-microcode - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update ships updated CPU microcode for some types of Intel CPUs
and provides mitigations for security vulnerabilities which could
result in privilege escalation in combination with VT-d and various
side channel attacks."
  );
  # https://salsa.debian.org/hmh/intel-microcode/-/blob/master/debian/README.Debian
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8b9d243a"
  );
  # https://security-tracker.debian.org/tracker/source-package/intel-microcode
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?019586d4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/intel-microcode"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2021/dsa-4934"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the intel-microcode packages.

For the stable distribution (buster), these problems have been fixed
in version 3.20210608.2~deb10u1.

Note that there are two reported regressions; for some CoffeeLake CPUs
this update may break iwlwifi
(https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/i
ssues/56) and some for Skylake R0/D0 CPUs on systems using a very
outdated firmware/BIOS, the system may hang on boot:
(https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/i
ssues/31)

If you are affected by those issues, you can recover by disabling
microcode loading on boot (as documented in README.Debian, also
available online at
https://salsa.debian.org/hmh/intel-microcode/-/blob/master/debian/READ
ME.Debian)"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24489");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:intel-microcode");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"10.0", prefix:"intel-microcode", reference:"3.20210608.2~deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
