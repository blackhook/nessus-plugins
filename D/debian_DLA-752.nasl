#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-752-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(96013);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/22");

  script_cve_id(
    "CVE-2016-5290",
    "CVE-2016-5291",
    "CVE-2016-5296",
    "CVE-2016-5297",
    "CVE-2016-9066",
    "CVE-2016-9074",
    "CVE-2016-9079"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/07/13");

  script_name(english:"Debian DLA-752-1 : icedove security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Multiple security issues have been found in Icedove, Debian's version
of the Mozilla Thunderbird mail client: Multiple memory safety errors,
same-origin policy bypass issues, integer overflows, buffer overflows
and use-after-frees may lead to the execution of arbitrary code or
denial of service.

For Debian 7 'Wheezy', these problems have been fixed in version
45.5.1-1~deb7u1.

We recommend that you upgrade your icedove packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2016/12/msg00027.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/wheezy/icedove");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox nsSMILTimeContainer::NotifyTimeChange() RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:calendar-google-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-extension");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (deb_check(release:"7.0", prefix:"calendar-google-provider", reference:"45.5.1-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedove", reference:"45.5.1-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedove-dbg", reference:"45.5.1-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedove-dev", reference:"45.5.1-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceowl-extension", reference:"45.5.1-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
