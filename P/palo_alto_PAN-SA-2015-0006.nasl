#TRUSTED 7b416a8a2d494353a74e2ba37f3c7f6c5c677a4a92c75cbf9bd10eba62706afbb776a89bb9a9927b89247240e44250945f6004f19c73af09ead9b11e251695637fa65cd464b922bede3d035b5c05a9039620212af2e6582440b7785e671a2d7d31258ca94b83fb8923853edb3e19118ba8ca4f401c6f0a4bbdb72d932a71ac57b636448b0f42c150d5c0651620aac7bd432b140301ef07e16792cd5179802d7a0422776902d9985213f2742d92f37d1f763df8ff93ec7081cea985ec475f540fc1142d4f8d9ea56fb54a4a51c427a75d5992680529c26d9e54e4ec2cac2adec6f96deb32c10fa27252c687f914f925d7a6de3d7f2a9d042c9883ded67686b9bcb69f355ce67e473800645e99b2f3183d953e51a3d72f7a4262bd54e5b31bd272e53c80d69c32e90add725217f7c888d6c12120d347ce7d2244bba16e6b6bc01c8720e34e29a80ace10340097326a49f00def8350a32a43d6a761f2d26f3f5e9723cb38be1888e5a4e5394b5edfc4834d8c1a54d7d81e7fc408b676f6213645a7ec0dac36b3eaa96abd88ea0222c0b94dce0138b6a1822334aa7eb0c5ed0f187ded8fc80fdad48bc885780753e5ae0031ebba7fbe6157c327219f69b44397c48ad4385b1448b6ac7826f56fab4c1e9cc52dcb846bdafcd7a6c1171199a9b6fdb8d4b900446cb06ab750138f7c4e563c8fd0b2d6fc52ce128a5e931e8562894e86
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86906);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/13");


  script_name(english:"Palo Alto Networks PAN-OS API Key Persistence Security Bypass (PAN-SA-2015-0006)");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an authentication security bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Palo Alto Networks PAN-OS running on the remote host is a version
prior to 6.1.7 or 7.x prior to 7.0.2. It is, therefore, affected by a
security bypass vulnerability due to a failure to invalidate the local
administrator API keys after a password change has been performed, the
old keys being valid up until the time the device is rebooted. A
remote attacker can exploit this to gain access to the management
interface.");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/33");
  # https://www.paloaltonetworks.com/documentation/70/pan-os/pan-os-release-notes/pan-os-7-0-2-addressed-issues.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83755f2d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 6.1.7 / 7.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Palo Alto Networks PAN-OS";
version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Version");
full_version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Full_Version");
fix = NULL;

# Ensure sufficient granularity.
if (
  version =~ "^6(\.1)?$" ||
  version =~ "^7(\.0)?$"
) audit(AUDIT_VER_NOT_GRANULAR, app_name, full_version);

if (version =~ "^7\.0\.")
{
  fix = "7.0.2";
}
else if (
  version =~ "^[0-5]($|[^0-9])" ||
  version =~ "^6\.0($|[^0-9])" ||
  version =~ "^6\.1\."
)
{
  fix = "6.1.7";
}
else
  audit(AUDIT_NOT_INST, app_name + " 0.x-6.1.x / 7.0.x");

# Compare version to fix and report as needed.
if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + full_version +
      '\n  Fixed versions    : ' + fix +
      '\n';
    security_warning(extra:report, port:0);
  }
  else security_warning(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);
