# application launcher to start apps in a restrictive sandbox #

sandbox-app-launcher runs each app as its own user, in a bubblewrap sandbox
and confined by apparmor.

The directory, `/shared`, is shared across all app sandboxes to transfer
files across.

This implements a permissions system to configure what apps can access.
There are currently 4 available permissions:

* Network access

* Webcam access

* Microphone access

* Shared storage access (read-only or read-write)

All apps the user installs will be automatically configured to run in
the sandbox and a prompt will ask the user which permissions they wish to
grant the application (not implemented yet).

Currently a WIP and not for actual use.
## How to install `sandbox-app-launcher` using apt-get ##

1\. Download [Whonix's Signing Key]().

```
wget https://www.whonix.org/patrick.asc
```

Users can [check Whonix Signing Key](https://www.whonix.org/wiki/Whonix_Signing_Key) for better security.

2\. Add Whonix's signing key.

```
sudo apt-key --keyring /etc/apt/trusted.gpg.d/whonix.gpg add ~/patrick.asc
```

3\. Add Whonix's APT repository.

```
echo "deb https://deb.whonix.org buster main contrib non-free" | sudo tee /etc/apt/sources.list.d/whonix.list
```

4\. Update your package lists.

```
sudo apt-get update
```

5\. Install `sandbox-app-launcher`.

```
sudo apt-get install sandbox-app-launcher
```

## How to Build deb Package from Source Code ##

Can be build using standard Debian package build tools such as:

```
dpkg-buildpackage -b
```

See [instructions](https://www.whonix.org/wiki/Dev/Build_Documentation/sandbox-app-launcher). (Replace `package-name` with the actual name of this package.)

## Contact ##

* [Free Forum Support](https://forums.whonix.org)
* [Professional Support](https://www.whonix.org/wiki/Professional_Support)

## Donate ##

`sandbox-app-launcher` requires [donations](https://www.whonix.org/wiki/Donate) to stay alive!
