#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4611. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(133326);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2020-7247");
  script_xref(name:"DSA", value:"4611");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");

  script_name(english:"Debian DSA-4611-1 : opensmtpd - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Qualys discovered that the OpenSMTPD SMTP server performed
insufficient validation of email addresses which could result in the
execution of arbitrary commands as root. In addition this update fixes
a denial of service by triggering an opportunistic TLS downgrade."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=950121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/opensmtpd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4611"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the opensmtpd packages.

For the oldstable distribution (stretch), these problems have been
fixed in version 6.0.2p1-2+deb9u2.

For the stable distribution (buster), these problems have been fixed
in version 6.0.3p1-5+deb10u3. This update also includes non-security
bugfixes which were already lined up for the Buster 10.3 point
release."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7247");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'OpenSMTPD MAIL FROM Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:opensmtpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"opensmtpd", reference:"6.0.3p1-5+deb10u3")) flag++;
if (deb_check(release:"9.0", prefix:"opensmtpd", reference:"6.0.2p1-2+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
