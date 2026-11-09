# Optional assets

`icon.png` is the default pen outline for the PDF stamp. The generated config uses `icon-path = "@bundled"` to find it beside the script. Set `icon-path = ""` to omit the icon.

Vendor smart-card middleware and installers can be kept here locally. Git ignores these files. Configure `[smartcard].module` with the path to the actual PKCS#11 shared library after following the vendor's installation instructions. Check the vendor's terms before redistributing any middleware.
