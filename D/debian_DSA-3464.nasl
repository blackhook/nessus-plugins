#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3464. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(88499);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/28");

  script_cve_id(
    "CVE-2015-3226",
    "CVE-2015-3227",
    "CVE-2015-7576",
    "CVE-2015-7577",
    "CVE-2015-7581",
    "CVE-2016-0751",
    "CVE-2016-0752",
    "CVE-2016-0753"
  );
  script_xref(name:"DSA", value:"3464");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");

  script_name(english:"Debian DSA-3464-1 : rails - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Multiple security issues have been discovered in the Ruby on Rails web
application development framework, which may result in denial of
service, cross-site scripting, information disclosure or bypass of
input validation.");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/rails");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2016/dsa-3464");
  script_set_attribute(attribute:"solution", value:
"Upgrade the rails packages.

For the stable distribution (jessie), these problems have been fixed
in version 2:4.1.8-1+deb8u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ruby on Rails Dynamic Render File Upload Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rails");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (deb_check(release:"8.0", prefix:"rails", reference:"2:4.1.8-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-actionmailer", reference:"2:4.1.8-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-actionpack", reference:"2:4.1.8-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-actionview", reference:"2:4.1.8-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-activemodel", reference:"2:4.1.8-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-activerecord", reference:"2:4.1.8-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-activesupport", reference:"2:4.1.8-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-activesupport-2.3", reference:"2:4.1.8-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-rails", reference:"2:4.1.8-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-railties", reference:"2:4.1.8-1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
