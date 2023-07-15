#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139374);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/06");

  script_name(english:"Red Hat Enterprise Linux CoreOS Unsupported Version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported version of Red Hat 
Enterprise Linux CoreOS.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Red Hat Enterprise 
Linux CoreOS on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/support/policy/updates/openshift");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Red Hat Enterprise Linux CoreOS that is 
currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Default unsupported software score.");
  script_set_attribute(attribute:"agent", value:"unix");

  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:redhat:enterprise_linux_coreos");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release");

  exit(0);
}

include('datetime.inc');

get_kb_item_or_exit("Host/local_checks_enabled");
release = get_kb_item_or_exit("Host/RedHat/release");

os = "Red Hat Enterprise Linux CoreOS";
if(os >!< release) audit(AUDIT_OS_NOT, os);

match = pregmatch(pattern:"^Red Hat Enterprise Linux CoreOS release (\d\.\d)$", string: release);
if(empty_or_null(match)) audit(AUDIT_UNKNOWN_DEVICE_VER, os);

ver = match[1];
TBD = 2140000000;
eol = {
  '4.1': mktime(year:2020, mon:5, mday:5),
  '4.2': mktime(year:2020, mon:7, mday:13),
  '4.3': TBD,
  '4.4': TBD,
  '4.5': TBD 
};

if(!eol[ver]) exit(0, strcat('Vendor support information is unknown for release: ', release));

if(int(gettimeofday()) < eol[ver])
  exit(0, strcat(chomp(release), ' is supported.'));

register_unsupported_product(
  product_name:  release, 
  cpe_class:     'o', 
  cpe_base:      "redhat:enterprise_linux_coreos",
  is_custom_cpe: TRUE
);

security_report_v4(
  port: 0, 
  extra: strcat(
    '\n  ', os, ' release : ', ver,
    '\n  End-of-life Date                        : ', strftime('%F', eol[ver])
  ),
  severity: SECURITY_HOLE
);
