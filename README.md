# Firewall for Whonix-Gateway and Whonix-Workstation #

iptables rules script and firewall configuration file for Whonix-Gateway and
Whonix-Workstation.

Whonix-Gateway Firewall Features:
- transparent proxying
- stream isolation
- reject invalid packages
- fail closed mechanism
- optional VPN-Firewall
- optional isolating proxy
- optional incoming flash proxy
- optional Tor relay

Do not remove, unless you no longer wish to use Whonix.
## How to install `whonix-firewall` using apt-get ##

1\. Add [Whonix's Signing Key](https://www.whonix.org/wiki/Whonix_Signing_Key).

```
sudo apt-key --keyring /etc/apt/trusted.gpg.d/whonix.gpg adv --keyserver hkp://ipv4.pool.sks-keyservers.net:80 --recv-keys 916B8D99C38EAF5E8ADC7A2A8D66066A2EEACCDA
```

3\. Add Whonix's APT repository.

```
echo "deb http://deb.whonix.org stretch main" | sudo tee /etc/apt/sources.list.d/whonix.list
```

4\. Update your package lists.

```
sudo apt-get update
```

5\. Install `whonix-firewall`.

```
sudo apt-get install whonix-firewall
```

## How to Build deb Package ##

Replace `apparmor-profile-torbrowser` with the actual name of this package with `whonix-firewall` and see [instructions](https://www.whonix.org/wiki/Dev/Build_Documentation/apparmor-profile-torbrowser).

## Contact ##

* [Free Forum Support](https://forums.whonix.org)
* [Professional Support](https://www.whonix.org/wiki/Professional_Support)

## Payments ##

`whonix-firewall` requires [payments](https://www.whonix.org/wiki/Payments) to stay alive!
