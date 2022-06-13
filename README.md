# CVE-2022-1972 infoleak PoC

Infoleak exploit for the CVE-2022-1972.

You can find the associated write-up on our [blog](https://www.randorisec.fr/yet-another-bug-netfilter/)

## Requirements

The user namespaces must be available for unprivileged users.

```
$ sysctl kernel.unprivileged_userns_clone
kernel.unprivileged_userns_clone = 1
```

## Build

```sh
make
```
