#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4522. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128782);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/27");

  script_cve_id("CVE-2018-19502", "CVE-2018-19503", "CVE-2018-19504", "CVE-2018-20194", "CVE-2018-20195", "CVE-2018-20197", "CVE-2018-20198", "CVE-2018-20357", "CVE-2018-20358", "CVE-2018-20359", "CVE-2018-20361", "CVE-2018-20362", "CVE-2019-15296");
  script_xref(name:"DSA", value:"4522");

  script_name(english:"Debian DSA-4522-1 : faad2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in faad2, the Freeware
Advanced Audio Coder. These vulnerabilities might allow remote
attackers to cause denial-of-service, or potentially execute arbitrary
code if crafted MPEG AAC files are processed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=914641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/faad2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/faad2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4522"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the faad2 packages.

For the oldstable distribution (stretch), these problems have been
fixed in version 2.8.0~cvs20161113-1+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:faad2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"faad", reference:"2.8.0~cvs20161113-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"faad2-dbg", reference:"2.8.0~cvs20161113-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libfaad-dev", reference:"2.8.0~cvs20161113-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libfaad2", reference:"2.8.0~cvs20161113-1+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
