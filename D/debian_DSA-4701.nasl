#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4701. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(137374);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/18");

  script_cve_id("CVE-2020-0543", "CVE-2020-0548", "CVE-2020-0549");
  script_xref(name:"DSA", value:"4701");

  script_name(english:"Debian DSA-4701-1 : intel-microcode - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update ships updated CPU microcode for some types of Intel CPUs
and provides mitigations for the Special Register Buffer Data Sampling
(CVE-2020-0543 ), Vector Register Sampling (CVE-2020-0548 ) and L1D
Eviction Sampling (CVE-2020-0549 ) hardware vulnerabilities.

The microcode update for HEDT and Xeon CPUs with signature 0x50654
which was reverted in DSA 4565-2 is now included again with a fixed
release.

The upstream update for Skylake-U/Y (signature 0x406e3) had to be
excluded from this update due to reported hangs on boot.

For details refer to
https://www.intel.com/content/www/us/en/security-center/advisory/intel
-sa-00320.html,
https://www.intel.com/content/www/us/en/security-center/advisory/intel
-sa-00329.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-0543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-0548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-0549"
  );
  # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00320.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c444b53b"
  );
  # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00329.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a852169"
  );
  # https://security-tracker.debian.org/tracker/source-package/intel-microcode
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?019586d4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/intel-microcode"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/intel-microcode"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4701"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the intel-microcode packages.

For the oldstable distribution (stretch), these problems have been
fixed in version 3.20200609.2~deb9u1.

For the stable distribution (buster), these problems have been fixed
in version 3.20200609.2~deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:intel-microcode");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"intel-microcode", reference:"3.20200609.2~deb10u1")) flag++;
if (deb_check(release:"9.0", prefix:"intel-microcode", reference:"3.20200609.2~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
