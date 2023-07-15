#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4070. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105430);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-17843", "CVE-2017-17844", "CVE-2017-17845", "CVE-2017-17846", "CVE-2017-17847", "CVE-2017-17848");
  script_xref(name:"DSA", value:"4070");

  script_name(english:"Debian DSA-4070-1 : enigmail - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in Enigmail, an OpenPGP
extension for Thunderbird, which could result in a loss of
confidentiality, faked signatures, plain text leaks and denial of
service. Additional information can be found under
https://enigmail.net/download/other/Enigmail%20Pentest%20Report%20by%2
0Cure53%20-%20Excerpt.pdf"
  );
  # https://enigmail.net/download/other/Enigmail%20Pentest%20Report%20by%20Cure53%20-%20Excerpt.pdf
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6620e35f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/enigmail"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/enigmail"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/enigmail"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-4070"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the enigmail packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 2:1.9.9-1~deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 2:1.9.9-1~deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:enigmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"enigmail", reference:"2:1.9.9-1~deb8u1")) flag++;
if (deb_check(release:"9.0", prefix:"enigmail", reference:"2:1.9.9-1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
